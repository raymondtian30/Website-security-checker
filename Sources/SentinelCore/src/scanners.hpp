#ifndef SENTINEL_SCANNERS_HPP
#define SENTINEL_SCANNERS_HPP

#include "types.hpp"
#include "http_client.hpp"
#include <functional>
#include <vector>

namespace sentinel {

using FindingEmitFn = std::function<void(const Finding&)>;

class Scanners {
public:
    static void run_tls_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit);
    static void run_headers_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit);
    static void run_auth_session_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit);
    static void run_csrf_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit);
    static void run_server_security_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit);
    static void run_info_disclosure_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit);
    static void run_api_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit);
    static void run_sqli_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit);
    static void run_xss_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit);
    static void run_owasp_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit);
};

} // namespace sentinel

#endif /* SENTINEL_SCANNERS_HPP */
