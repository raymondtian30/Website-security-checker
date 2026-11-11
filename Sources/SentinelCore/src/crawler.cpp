#include "crawler.hpp"
#include "scope_guard.hpp"
#include <algorithm>
#include <cctype>
#include <queue>
#include <regex>

namespace sentinel {

static std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static bool is_csrf_field_name(const std::string& name) {
    std::string n = lower_copy(name);
    return n.find("csrf") != std::string::npos ||
           n.find("xsrf") != std::string::npos ||
           n == "_token" ||
           n == "authenticity_token" ||
           n == "__requestverificationtoken" ||
           n.find(" anti_forgery") != std::string::npos ||
           n.find("nonce") != std::string::npos;
}

static void extract_forms(const ParsedURL& page_parsed, const std::string& html, std::vector<DiscoveredForm>& forms) {
    static const std::regex form_re(R"(<form\b([^>]*)>([\s\S]*?)</form>)", std::regex::icase);
    static const std::regex action_re(R"(\baction\s*=\s*["']([^"']*)["'])", std::regex::icase);
    static const std::regex method_re(R"(\bmethod\s*=\s*["']?([A-Za-z]+)["']?)", std::regex::icase);
    static const std::regex input_re(R"(<input\b([^>]*)>)", std::regex::icase);
    static const std::regex name_re(R"(\bname\s*=\s*["']([^"']+)["'])", std::regex::icase);
    static const std::regex type_re(R"(\btype\s*=\s*["']?([A-Za-z0-9_\-]+)["']?)", std::regex::icase);

    auto begin = std::sregex_iterator(html.begin(), html.end(), form_re);
    auto end = std::sregex_iterator();

    for (auto it = begin; it != end; ++it) {
        std::string attrs = (*it)[1].str();
        std::string inner = (*it)[2].str();

        DiscoveredForm form;
        form.page_url = page_parsed.full_url();
        form.action_url = form.page_url;
        form.method = "GET";

        std::smatch m;
        if (std::regex_search(attrs, m, action_re)) {
            std::string resolved = ScopeGuard::resolve_relative_url(page_parsed, m[1].str());
            if (!resolved.empty()) form.action_url = resolved;
        }
        if (std::regex_search(attrs, m, method_re)) {
            std::string meth = m[1].str();
            std::transform(meth.begin(), meth.end(), meth.begin(), [](unsigned char c) { return std::toupper(c); });
            form.method = meth;
        }

        auto in_begin = std::sregex_iterator(inner.begin(), inner.end(), input_re);
        for (auto iit = in_begin; iit != end; ++iit) {
            std::string iattrs = (*iit)[1].str();
            std::string iname;
            std::string itype = "text";
            if (std::regex_search(iattrs, m, name_re)) iname = m[1].str();
            if (std::regex_search(iattrs, m, type_re)) itype = lower_copy(m[1].str());

            if (!iname.empty()) {
                form.inputs.push_back({iname, itype});
                if (is_csrf_field_name(iname)) {
                    form.has_csrf_token = true;
                }
            }
            if (itype == "password") {
                form.has_password_field = true;
            }
        }
        forms.push_back(form);
    }
}

CrawlData Crawler::crawl(
    const ScanConfig& config,
    HttpClient& client,
    std::function<void(int endpoints_examined)> on_progress
) {
    CrawlData data;

    int max_pages = config.max_crawl_pages;
    if (config.intensity == "Passive") {
        max_pages = 3;
    } else if (config.intensity == "Thorough") {
        max_pages = std::max(config.max_crawl_pages, 40);
    }

    std::queue<std::string> queue;
    std::set<std::string> queued;

    ParsedURL seed = ScopeGuard::parse_url(config.target_url);
    if (!seed.valid) return data;

    std::string seed_full = seed.full_url();
    queue.push(seed_full);
    queued.insert(seed_full);

    static const std::regex href_re(R"(\b(?:href|action|src)\s*=\s*["']([^"'#]+)["'])", std::regex::icase);
    static const std::regex fetch_api_re(R"((?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["'](/[^"']+|https?://[^"']+)["'])", std::regex::icase);

    while (!queue.empty() && (int)data.visited_urls.size() < max_pages) {
        if (client.is_cancelled_or_timed_out()) break;

        std::string current = queue.front();
        queue.pop();

        ScopeValidationResult scope_res = ScopeGuard::validate_url(config, current);
        if (!scope_res.allowed) continue;

        HttpResponse resp = client.request("GET", current);
        if (!resp.success) continue;

        data.visited_urls.push_back(current);
        data.responses[current] = resp;

        if (!scope_res.parsed.query.empty()) {
            data.parameterized_urls.insert(current);
        }
        if (scope_res.parsed.path.find("/api/") != std::string::npos ||
            scope_res.parsed.path.find("/graphql") != std::string::npos ||
            (resp.headers.count("content-type") &&
             resp.headers["content-type"].find("application/json") != std::string::npos)) {
            data.api_endpoints.insert(current);
        }

        if (on_progress) {
            on_progress((int)data.visited_urls.size());
        }

        // Only parse HTML bodies for links/forms
        std::string ctype = resp.headers.count("content-type") ? lower_copy(resp.headers["content-type"]) : "";
        if (ctype.find("html") != std::string::npos || resp.body.find("<html") != std::string::npos || resp.body.find("<form") != std::string::npos || resp.body.find("<a ") != std::string::npos) {
            extract_forms(scope_res.parsed, resp.body, data.forms);

            // Convert GET forms with inputs into parameterized URLs for testing
            for (const auto& f : data.forms) {
                if (f.page_url == current && f.method == "GET" && !f.inputs.empty()) {
                    ParsedURL fp = ScopeGuard::parse_url(f.action_url);
                    if (fp.valid && fp.query.empty()) {
                        std::ostringstream q;
                        for (size_t i = 0; i < f.inputs.size(); ++i) {
                            if (i > 0) q << "&";
                            q << f.inputs[i].first << "=1";
                        }
                        fp.query = q.str();
                        std::string param_url = fp.full_url();
                        if (ScopeGuard::validate_url(config, param_url).allowed) {
                            data.parameterized_urls.insert(param_url);
                        }
                    }
                }
            }

            auto begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), href_re);
            auto end = std::sregex_iterator();
            for (auto it = begin; it != end; ++it) {
                std::string raw_link = (*it)[1].str();
                std::string resolved = ScopeGuard::resolve_relative_url(scope_res.parsed, raw_link);
                if (resolved.empty()) continue;

                if (raw_link.find(".js") != std::string::npos) {
                    data.script_urls.insert(resolved);
                }

                // Skip static media assets for page crawling
                std::string low_res = lower_copy(resolved);
                if (low_res.find(".png") != std::string::npos || low_res.find(".jpg") != std::string::npos ||
                    low_res.find(".jpeg") != std::string::npos || low_res.find(".gif") != std::string::npos ||
                    low_res.find(".svg") != std::string::npos || low_res.find(".ico") != std::string::npos ||
                    low_res.find(".woff") != std::string::npos || low_res.find(".ttf") != std::string::npos) {
                    continue;
                }

                ScopeValidationResult link_scope = ScopeGuard::validate_url(config, resolved);
                if (!link_scope.allowed) continue;

                std::string canonical = link_scope.parsed.full_url();
                if (!link_scope.parsed.query.empty()) {
                    data.parameterized_urls.insert(canonical);
                }
                if (link_scope.parsed.path.find("/api/") != std::string::npos) {
                    data.api_endpoints.insert(canonical);
                }
                if (queued.find(canonical) == queued.end() && (int)queued.size() < max_pages * 2) {
                    queued.insert(canonical);
                    queue.push(canonical);
                }
            }

            auto f_begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), fetch_api_re);
            for (auto it = f_begin; it != end; ++it) {
                std::string resolved = ScopeGuard::resolve_relative_url(scope_res.parsed, (*it)[1].str());
                if (!resolved.empty() && ScopeGuard::validate_url(config, resolved).allowed) {
                    data.api_endpoints.insert(resolved);
                    if (queued.find(resolved) == queued.end()) {
                        queued.insert(resolved);
                        queue.push(resolved);
                    }
                }
            }
        }
    }

    return data;
}

} // namespace sentinel
