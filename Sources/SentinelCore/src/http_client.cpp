#include "http_client.hpp"
#include "scope_guard.hpp"
#include <curl/curl.h>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <thread>

namespace sentinel {

static std::string to_lower_str(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static std::string trim_str(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace((unsigned char)s[start])) ++start;
    size_t end = s.size();
    while (end > start && std::isspace((unsigned char)s[end - 1])) --end;
    return s.substr(start, end - start);
}

static size_t write_body_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    size_t total = size * nmemb;
    std::string* body = static_cast<std::string*>(userdata);
    const size_t max_body_size = 512 * 1024; // 512 KB cap
    if (body->size() < max_body_size) {
        size_t to_append = std::min(total, max_body_size - body->size());
        body->append(ptr, to_append);
    }
    return total;
}

struct HeaderCapture {
    std::map<std::string, std::string>* headers = nullptr;
    std::vector<std::string>* set_cookies = nullptr;
};

static size_t write_header_cb(char* buffer, size_t size, size_t nitems, void* userdata) {
    size_t total = size * nitems;
    HeaderCapture* cap = static_cast<HeaderCapture*>(userdata);
    std::string line(buffer, total);
    auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string name = to_lower_str(trim_str(line.substr(0, colon)));
        std::string val = trim_str(line.substr(colon + 1));
        if (name == "set-cookie") {
            cap->set_cookies->push_back(val);
        }
        (*cap->headers)[name] = val;
    }
    return total;
}

HttpClient::HttpClient(
    const ScanConfig& config,
    std::atomic<bool>& cancel_flag,
    std::atomic<bool>& pause_flag,
    std::chrono::steady_clock::time_point deadline
)
    : config_(config),
      cancel_flag_(cancel_flag),
      pause_flag_(pause_flag),
      deadline_(deadline),
      last_request_time_(std::chrono::steady_clock::now() - std::chrono::seconds(10)) {}

bool HttpClient::is_cancelled_or_timed_out() const {
    if (cancel_flag_.load()) return true;
    if (std::chrono::steady_clock::now() >= deadline_) return true;
    return false;
}

void HttpClient::wait_if_paused() const {
    while (pause_flag_.load() && !cancel_flag_.load()) {
        if (std::chrono::steady_clock::now() >= deadline_) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void HttpClient::enforce_rate_limit() {
    std::lock_guard<std::mutex> lock(rate_mutex_);
    int rps = std::max(1, std::min(50, config_.max_requests_per_second));
    auto min_interval = std::chrono::milliseconds(1000 / rps);
    auto now = std::chrono::steady_clock::now();
    auto elapsed = now - last_request_time_;
    if (elapsed < min_interval) {
        std::this_thread::sleep_for(min_interval - elapsed);
    }
    last_request_time_ = std::chrono::steady_clock::now();
}

HttpResponse HttpClient::perform_single_request(
    const std::string& method,
    const ScopeValidationResult& scope_res,
    const std::vector<std::pair<std::string, std::string>>& extra_headers,
    const std::string& req_body
) {
    HttpResponse resp;
    resp.final_url = scope_res.parsed.full_url();

    CURL* curl = curl_easy_init();
    if (!curl) {
        resp.error_message = "Failed to initialize libcurl";
        return resp;
    }

    auto start_t = std::chrono::steady_clock::now();

    curl_easy_setopt(curl, CURLOPT_URL, resp.final_url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L); // Manual redirect validation
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)std::max(2, config_.request_timeout_seconds));
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)std::max(3, config_.request_timeout_seconds));
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Sentinel-Security-Auditor/1.0 (Authorized-Assessment; macOS)");
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);

    // Pin the validated IP via CURLOPT_RESOLVE to defeat DNS rebinding
    struct curl_slist* resolve_list = nullptr;
    if (!scope_res.resolved_ip.empty()) {
        std::ostringstream pin;
        pin << scope_res.parsed.host << ":" << scope_res.parsed.port << ":" << scope_res.resolved_ip;
        resolve_list = curl_slist_append(resolve_list, pin.str().c_str());
        curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve_list);
    }

    if (method == "HEAD") {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    } else if (method != "GET") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
        if (!req_body.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_body.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)req_body.size());
        }
    }

    struct curl_slist* req_headers = nullptr;
    for (const auto& kv : extra_headers) {
        std::string h = kv.first + ": " + kv.second;
        req_headers = curl_slist_append(req_headers, h.c_str());
    }
    if (req_headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_headers);
    }

    HeaderCapture hcap{&resp.headers, &resp.set_cookies};
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hcap);

    CURLcode res = curl_easy_perform(curl);

    // If HTTPS failed solely due to self-signed/untrusted certificate, record ssl_verify_ok = false
    // and retry with verification disabled so headers/body can still be audited while flagging TLS failure.
    if (res == CURLE_SSL_CACERT || res == CURLE_SSL_PEER_CERTIFICATE || res == CURLE_SSL_CACERT_BADFILE) {
        resp.ssl_verify_ok = false;
        resp.ssl_verify_result = 1;
        resp.body.clear();
        resp.headers.clear();
        resp.set_cookies.clear();
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        res = curl_easy_perform(curl);
    } else {
        long verify_res = 0;
        curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &verify_res);
        resp.ssl_verify_result = verify_res;
        resp.ssl_verify_ok = (verify_res == 0);
    }

    if (res == CURLE_OK) {
        resp.success = true;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp.status_code);

        struct curl_certinfo* certinfo = nullptr;
        if (curl_easy_getinfo(curl, CURLINFO_CERTINFO, &certinfo) == CURLE_OK && certinfo && certinfo->num_of_certs > 0) {
            std::ostringstream cinfo;
            for (struct curl_slist* sl = certinfo->certinfo[0]; sl; sl = sl->next) {
                std::string entry(sl->data ? sl->data : "");
                if (entry.rfind("Subject:", 0) == 0 || entry.rfind("Issuer:", 0) == 0 ||
                    entry.rfind("Start date:", 0) == 0 || entry.rfind("Expire date:", 0) == 0) {
                    cinfo << entry << "; ";
                }
            }
            resp.cert_info_summary = cinfo.str();
        }
    } else {
        resp.success = false;
        resp.error_message = curl_easy_strerror(res);
    }

    auto end_t = std::chrono::steady_clock::now();
    resp.elapsed_ms = std::chrono::duration<double, std::milli>(end_t - start_t).count();

    if (req_headers) curl_slist_free_all(req_headers);
    if (resolve_list) curl_slist_free_all(resolve_list);
    curl_easy_cleanup(curl);
    return resp;
}

HttpResponse HttpClient::request(
    const std::string& method,
    const std::string& url,
    const std::vector<std::pair<std::string, std::string>>& extra_headers,
    const std::string& body,
    bool follow_redirects
) {
    HttpResponse resp;
    std::string current_url = url;
    std::string current_method = method;
    int redirect_count = 0;

    while (true) {
        wait_if_paused();
        if (is_cancelled_or_timed_out()) {
            resp.error_message = "Scan cancelled or maximum duration reached.";
            return resp;
        }

        ScopeValidationResult scope_res = ScopeGuard::validate_url(config_, current_url);
        if (!scope_res.allowed) {
            if (redirect_count > 0) {
                resp.redirect_blocked = true;
                resp.blocked_redirect_reason = scope_res.reason;
            }
            resp.error_message = scope_res.reason;
            return resp;
        }

        enforce_rate_limit();
        resp = perform_single_request(current_method, scope_res, extra_headers, body);
        if (!resp.success || !follow_redirects) {
            return resp;
        }

        // Check if status is 3xx redirect
        if (resp.status_code == 301 || resp.status_code == 302 ||
            resp.status_code == 303 || resp.status_code == 307 || resp.status_code == 308) {
            auto loc_it = resp.headers.find("location");
            if (loc_it == resp.headers.end() || loc_it->second.empty()) {
                return resp;
            }

            if (redirect_count >= config_.max_redirects) {
                resp.error_message = "Maximum redirect limit reached.";
                return resp;
            }

            std::string next_url = ScopeGuard::resolve_relative_url(scope_res.parsed, loc_it->second);
            if (next_url.empty()) {
                resp.redirect_blocked = true;
                resp.blocked_redirect_reason = "Invalid redirect Location header: " + loc_it->second;
                return resp;
            }

            // Re-validate redirect target before following
            ScopeValidationResult next_scope = ScopeGuard::validate_url(config_, next_url);
            if (!next_scope.allowed) {
                resp.redirect_blocked = true;
                resp.blocked_redirect_reason = next_scope.reason;
                return resp;
            }

            current_url = next_scope.parsed.full_url();
            if (resp.status_code == 303 || ((resp.status_code == 301 || resp.status_code == 302) && current_method == "POST")) {
                current_method = "GET";
            }
            ++redirect_count;
            continue;
        }

        break;
    }

    return resp;
}

} // namespace sentinel
