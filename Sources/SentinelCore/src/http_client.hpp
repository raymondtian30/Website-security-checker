#ifndef SENTINEL_HTTP_CLIENT_HPP
#define SENTINEL_HTTP_CLIENT_HPP

#include "types.hpp"
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <vector>

namespace sentinel {

class HttpClient {
public:
    HttpClient(
        const ScanConfig& config,
        std::atomic<bool>& cancel_flag,
        std::atomic<bool>& pause_flag,
        std::chrono::steady_clock::time_point deadline
    );

    HttpResponse request(
        const std::string& method,
        const std::string& url,
        const std::vector<std::pair<std::string, std::string>>& extra_headers = {},
        const std::string& body = "",
        bool follow_redirects = true
    );

    bool is_cancelled_or_timed_out() const;
    void wait_if_paused() const;

private:
    const ScanConfig& config_;
    std::atomic<bool>& cancel_flag_;
    std::atomic<bool>& pause_flag_;
    std::chrono::steady_clock::time_point deadline_;
    mutable std::mutex rate_mutex_;
    std::chrono::steady_clock::time_point last_request_time_;

    void enforce_rate_limit();
    HttpResponse perform_single_request(
        const std::string& method,
        const ScopeValidationResult& scope_res,
        const std::vector<std::pair<std::string, std::string>>& extra_headers,
        const std::string& body
    );
};

} // namespace sentinel

#endif /* SENTINEL_HTTP_CLIENT_HPP */
