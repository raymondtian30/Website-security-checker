#ifndef SENTINEL_TYPES_HPP
#define SENTINEL_TYPES_HPP

#include <string>
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <iomanip>

namespace sentinel {

struct ScanConfig {
    std::string target_url;
    std::string target_domain;
    bool authorized = false;
    bool include_subdomains = false;
    std::vector<std::string> allowed_subdomains;
    std::vector<std::string> excluded_paths = {"/logout", "/signout", "/delete"};
    std::vector<std::string> enabled_categories;
    std::string intensity = "Standard"; // Passive, Standard, Thorough
    int max_duration_seconds = 120;
    int max_requests_per_second = 10;
    int request_timeout_seconds = 8;
    int max_redirects = 5;
    int max_crawl_pages = 25;
    bool allow_local_testbench = false;
};

struct ParsedURL {
    bool valid = false;
    std::string scheme;
    std::string host;
    int port = 80;
    std::string path = "/";
    std::string query;

    std::string base_url() const {
        std::ostringstream oss;
        oss << scheme << "://" << host;
        if ((scheme == "http" && port != 80) || (scheme == "https" && port != 443)) {
            oss << ":" << port;
        }
        return oss.str();
    }

    std::string full_url() const {
        std::ostringstream oss;
        oss << base_url() << (path.empty() ? "/" : path);
        if (!query.empty()) {
            oss << "?" << query;
        }
        return oss.str();
    }
};

struct ScopeValidationResult {
    bool allowed = false;
    std::string reason;
    std::string resolved_ip;
    ParsedURL parsed;
};

struct HttpResponse {
    bool success = false;
    long status_code = 0;
    std::string final_url;
    std::string body;
    std::map<std::string, std::string> headers; // lowercase header name -> value
    std::vector<std::string> set_cookies;
    std::string error_message;
    bool redirect_blocked = false;
    std::string blocked_redirect_reason;
    bool ssl_verify_ok = true;
    long ssl_verify_result = 0;
    std::string cert_info_summary;
    double elapsed_ms = 0.0;
};

struct DiscoveredForm {
    std::string page_url;
    std::string action_url;
    std::string method = "GET";
    std::vector<std::pair<std::string, std::string>> inputs; // name, type
    bool has_csrf_token = false;
    bool has_password_field = false;
};

struct CrawlData {
    std::vector<std::string> visited_urls;
    std::map<std::string, HttpResponse> responses;
    std::vector<DiscoveredForm> forms;
    std::set<std::string> parameterized_urls;
    std::set<std::string> api_endpoints;
    std::set<std::string> script_urls;
};

struct Finding {
    std::string id;
    std::string root_cause_key;
    std::string title;
    std::string category;
    std::string owasp_category;
    std::string severity;       // Critical, High, Medium, Low, Informational
    std::string confidence;     // High, Medium, Low
    std::string status;         // Verified, Suspected, Informational, ManualReviewRequired, Incomplete
    double cvss_score = 0.0;
    std::string affected_url;
    std::string affected_parameter;
    std::string evidence;
    std::string technical_explanation;
    std::string impact;
    std::string safe_reproduction;
    std::string remediation;
};

struct ScanProgress {
    std::string current_module;
    std::string status; // Running, Paused, Completed, Cancelled, Failed
    int endpoints_examined = 0;
    int checks_completed = 0;
    int total_checks = 10;
    int findings_count = 0;
    double coverage_percent = 0.0;
    int elapsed_seconds = 0;
    int estimated_remaining_seconds = 0;
};

inline std::string json_escape(const std::string& s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (c < 0x20) {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

inline std::string deterministic_hash_id(const std::string& input) {
    uint64_t hash = 14695981039346656037ULL;
    for (unsigned char c : input) {
        hash ^= c;
        hash *= 1099511628211ULL;
    }
    std::ostringstream oss;
    oss << "FND-" << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << hash;
    return oss.str();
}

} // namespace sentinel

#endif /* SENTINEL_TYPES_HPP */
