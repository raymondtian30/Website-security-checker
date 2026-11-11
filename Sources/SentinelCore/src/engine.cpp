#include "engine.hpp"
#include "crawler.hpp"
#include "http_client.hpp"
#include "scanners.hpp"
#include "scope_guard.hpp"
#include <chrono>
#include <regex>
#include <set>
#include <sstream>

namespace sentinel {

Engine::Engine() = default;

void Engine::pause() { pause_flag_.store(true); }
void Engine::resume() { pause_flag_.store(false); }
void Engine::cancel() { cancel_flag_.store(true); }

static std::string unescape_json_str(const std::string& val) {
    std::string out;
    for (size_t i = 0; i < val.size(); ++i) {
        if (val[i] == '\\' && i + 1 < val.size()) {
            ++i;
            out.push_back(val[i]);
        } else {
            out.push_back(val[i]);
        }
    }
    return out;
}

static std::string extract_json_string(const std::string& json, const std::string& key, const std::string& def = "") {
    std::regex re("\"" + key + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
    std::smatch m;
    if (std::regex_search(json, m, re)) {
        return unescape_json_str(m[1].str());
    }
    return def;
}

static bool extract_json_bool(const std::string& json, const std::string& key, bool def = false) {
    std::regex re("\"" + key + "\"\\s*:\\s*(true|false)");
    std::smatch m;
    if (std::regex_search(json, m, re)) {
        return m[1].str() == "true";
    }
    return def;
}

static int extract_json_int(const std::string& json, const std::string& key, int def) {
    std::regex re("\"" + key + "\"\\s*:\\s*(-?[0-9]+)");
    std::smatch m;
    if (std::regex_search(json, m, re)) {
        try {
            return std::stoi(m[1].str());
        } catch (...) {
            return def;
        }
    }
    return def;
}

static std::vector<std::string> extract_json_string_array(const std::string& json, const std::string& key) {
    std::vector<std::string> res;
    std::regex arr_re("\"" + key + "\"\\s*:\\s*\\[([^\\]]*)\\]");
    std::smatch m;
    if (std::regex_search(json, m, arr_re)) {
        std::string inner = m[1].str();
        std::regex item_re("\"((?:[^\"\\\\]|\\\\.)*)\"");
        auto begin = std::sregex_iterator(inner.begin(), inner.end(), item_re);
        auto end = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            res.push_back(unescape_json_str((*it)[1].str()));
        }
    }
    return res;
}

ScanConfig Engine::parse_config_json(const std::string& json) {
    ScanConfig cfg;
    cfg.target_url = extract_json_string(json, "targetURL");
    cfg.target_domain = extract_json_string(json, "targetDomain");
    cfg.authorized = extract_json_bool(json, "authorized", false);
    cfg.include_subdomains = extract_json_bool(json, "includeSubdomains", false);
    cfg.allowed_subdomains = extract_json_string_array(json, "allowedSubdomains");
    auto excl = extract_json_string_array(json, "excludedPaths");
    if (!excl.empty()) {
        cfg.excluded_paths = excl;
    }
    cfg.enabled_categories = extract_json_string_array(json, "enabledCategories");
    cfg.intensity = extract_json_string(json, "intensity", "Standard");
    cfg.max_duration_seconds = extract_json_int(json, "maxDurationSeconds", 120);
    cfg.max_requests_per_second = extract_json_int(json, "maxRequestsPerSecond", 10);
    cfg.request_timeout_seconds = extract_json_int(json, "requestTimeoutSeconds", 8);
    cfg.max_redirects = extract_json_int(json, "maxRedirects", 5);
    cfg.max_crawl_pages = extract_json_int(json, "maxCrawlPages", 25);
    cfg.allow_local_testbench = extract_json_bool(json, "allowLocalTestbench", false);
    return cfg;
}

std::string Engine::serialize_finding_json(const Finding& f) {
    std::ostringstream oss;
    oss << "{"
        << "\"id\":\"" << json_escape(f.id) << "\","
        << "\"rootCauseKey\":\"" << json_escape(f.root_cause_key) << "\","
        << "\"title\":\"" << json_escape(f.title) << "\","
        << "\"category\":\"" << json_escape(f.category) << "\","
        << "\"owaspCategory\":\"" << json_escape(f.owasp_category) << "\","
        << "\"severity\":\"" << json_escape(f.severity) << "\","
        << "\"confidence\":\"" << json_escape(f.confidence) << "\","
        << "\"status\":\"" << json_escape(f.status) << "\","
        << "\"cvssScore\":" << std::fixed << std::setprecision(1) << f.cvss_score << ","
        << "\"affectedURL\":\"" << json_escape(f.affected_url) << "\","
        << "\"affectedParameter\":\"" << json_escape(f.affected_parameter) << "\","
        << "\"evidence\":\"" << json_escape(f.evidence) << "\","
        << "\"technicalExplanation\":\"" << json_escape(f.technical_explanation) << "\","
        << "\"impact\":\"" << json_escape(f.impact) << "\","
        << "\"safeReproduction\":\"" << json_escape(f.safe_reproduction) << "\","
        << "\"remediation\":\"" << json_escape(f.remediation) << "\""
        << "}";
    return oss.str();
}

std::string Engine::serialize_progress_json(const ScanProgress& p) {
    std::ostringstream oss;
    oss << "{"
        << "\"currentModule\":\"" << json_escape(p.current_module) << "\","
        << "\"status\":\"" << json_escape(p.status) << "\","
        << "\"endpointsExamined\":" << p.endpoints_examined << ","
        << "\"checksCompleted\":" << p.checks_completed << ","
        << "\"totalChecks\":" << p.total_checks << ","
        << "\"findingsCount\":" << p.findings_count << ","
        << "\"coveragePercent\":" << std::fixed << std::setprecision(1) << p.coverage_percent << ","
        << "\"elapsedSeconds\":" << p.elapsed_seconds << ","
        << "\"estimatedRemainingSeconds\":" << p.estimated_remaining_seconds
        << "}";
    return oss.str();
}

std::string Engine::run_scan(
    const ScanConfig& config,
    std::function<void(const std::string&)> on_progress_json,
    std::function<void(const std::string&)> on_finding_json
) {
    cancel_flag_.store(false);
    pause_flag_.store(false);

    auto start_time = std::chrono::steady_clock::now();
    auto deadline = start_time + std::chrono::seconds(std::max(5, config.max_duration_seconds));

    // Validate authorization & initial URL scope
    ScopeValidationResult initial_scope = ScopeGuard::validate_url(config, config.target_url);
    if (!initial_scope.allowed) {
        std::ostringstream err;
        err << "{"
            << "\"success\":false,"
            << "\"status\":\"Failed\","
            << "\"error\":\"" << json_escape(initial_scope.reason) << "\","
            << "\"endpointsExamined\":0,"
            << "\"checksCompleted\":0,"
            << "\"totalChecks\":10,"
            << "\"coveragePercent\":0.0"
            << "}";
        return err.str();
    }

    HttpClient client(config, cancel_flag_, pause_flag_, deadline);

    struct ScannerTask {
        std::string name;
        std::function<void(const ScanConfig&, const CrawlData&, HttpClient&, FindingEmitFn)> fn;
    };

    std::vector<ScannerTask> all_tasks = {
        {"TLS / HTTPS", Scanners::run_tls_scanner},
        {"Security Headers", Scanners::run_headers_scanner},
        {"Authentication & Session", Scanners::run_auth_session_scanner},
        {"CSRF", Scanners::run_csrf_scanner},
        {"Server-Side Security", Scanners::run_server_security_scanner},
        {"Information Disclosure", Scanners::run_info_disclosure_scanner},
        {"API Security", Scanners::run_api_scanner},
        {"SQL Injection", Scanners::run_sqli_scanner},
        {"Cross-Site Scripting (XSS)", Scanners::run_xss_scanner},
        {"OWASP Top 10", Scanners::run_owasp_scanner}
    };

    std::vector<ScannerTask> enabled_tasks;
    if (config.enabled_categories.empty()) {
        enabled_tasks = all_tasks;
    } else {
        std::set<std::string> enabled_set(config.enabled_categories.begin(), config.enabled_categories.end());
        for (const auto& t : all_tasks) {
            if (enabled_set.count(t.name)) {
                enabled_tasks.push_back(t);
            }
        }
        if (enabled_tasks.empty()) {
            enabled_tasks = all_tasks;
        }
    }

    ScanProgress prog;
    prog.total_checks = (int)enabled_tasks.size();
    prog.status = "Running";
    prog.current_module = "Endpoint Discovery & Crawling";

    auto emit_progress = [&]() {
        auto now = std::chrono::steady_clock::now();
        prog.elapsed_seconds = (int)std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        prog.coverage_percent = prog.total_checks > 0
            ? ((double)prog.checks_completed / (double)prog.total_checks) * 100.0
            : 0.0;
        if (prog.checks_completed > 0 && prog.checks_completed < prog.total_checks) {
            double avg_per_check = (double)std::max(1, prog.elapsed_seconds) / (double)prog.checks_completed;
            prog.estimated_remaining_seconds = (int)(avg_per_check * (prog.total_checks - prog.checks_completed));
        } else {
            prog.estimated_remaining_seconds = 0;
        }
        if (on_progress_json) {
            on_progress_json(serialize_progress_json(prog));
        }
    };

    emit_progress();

    CrawlData crawl = Crawler::crawl(config, client, [&](int examined) {
        prog.endpoints_examined = examined;
        emit_progress();
    });

    if (crawl.visited_urls.empty() && !client.is_cancelled_or_timed_out()) {
        std::ostringstream err;
        err << "{"
            << "\"success\":false,"
            << "\"status\":\"Failed\","
            << "\"error\":\"Unable to reach target URL within scope and timeout constraints.\","
            << "\"endpointsExamined\":0,"
            << "\"checksCompleted\":0,"
            << "\"totalChecks\":" << prog.total_checks << ","
            << "\"coveragePercent\":0.0"
            << "}";
        return err.str();
    }

    std::set<std::string> emitted_ids;
    auto emit_finding = [&](const Finding& f) {
        if (emitted_ids.insert(f.id).second) {
            ++prog.findings_count;
            if (on_finding_json) {
                on_finding_json(serialize_finding_json(f));
            }
        }
    };

    for (size_t i = 0; i < enabled_tasks.size(); ++i) {
        client.wait_if_paused();
        if (client.is_cancelled_or_timed_out()) {
            // Emit Incomplete check notice for remaining modules so untested checks are never marked as passing
            Finding inc;
            inc.root_cause_key = "INCOMPLETE_" + enabled_tasks[i].name;
            inc.title = "Check Not Completed: " + enabled_tasks[i].name;
            inc.category = enabled_tasks[i].name;
            inc.owasp_category = "A05:2021-Security Misconfiguration";
            inc.severity = "Informational";
            inc.confidence = "High";
            inc.status = "Incomplete";
            inc.cvss_score = 0.0;
            inc.affected_url = config.target_url;
            inc.affected_parameter = enabled_tasks[i].name;
            inc.evidence = "Module skipped because scan was cancelled or reached maximum duration.";
            inc.technical_explanation = "This security check module did not complete execution and is not counted as passing.";
            inc.impact = "Potential vulnerabilities in this category remain untested.";
            inc.safe_reproduction = "Re-run the scan with a higher maximum duration or without cancelling.";
            inc.remediation = "Complete the scan for full coverage.";
            inc.id = deterministic_hash_id(inc.root_cause_key + "|" + inc.affected_url);
            emit_finding(inc);
            continue;
        }

        prog.current_module = enabled_tasks[i].name;
        emit_progress();

        enabled_tasks[i].fn(config, crawl, client, emit_finding);

        if (!client.is_cancelled_or_timed_out()) {
            ++prog.checks_completed;
        }
        emit_progress();
    }

    prog.status = cancel_flag_.load() ? "Cancelled" : "Completed";
    prog.current_module = prog.status;
    emit_progress();

    std::ostringstream summary;
    summary << "{"
            << "\"success\":true,"
            << "\"status\":\"" << prog.status << "\","
            << "\"error\":\"\","
            << "\"endpointsExamined\":" << prog.endpoints_examined << ","
            << "\"checksCompleted\":" << prog.checks_completed << ","
            << "\"totalChecks\":" << prog.total_checks << ","
            << "\"findingsCount\":" << prog.findings_count << ","
            << "\"coveragePercent\":" << std::fixed << std::setprecision(1) << prog.coverage_percent
            << "}";
    return summary.str();
}

} // namespace sentinel
