#ifndef SENTINEL_SCOPE_GUARD_HPP
#define SENTINEL_SCOPE_GUARD_HPP

#include "types.hpp"
#include <string>

namespace sentinel {

class ScopeGuard {
public:
    static ParsedURL parse_url(const std::string& raw_url);
    static std::string resolve_relative_url(const ParsedURL& base, const std::string& href);
    static ScopeValidationResult validate_url(const ScanConfig& config, const std::string& candidate_url);
    static bool is_ipv4_forbidden(uint32_t ipv4_host_order, bool allow_loopback, std::string& reason);
    static bool is_ip_string_allowed(const std::string& ip_str, bool allow_loopback, std::string& reason);
    static std::string normalize_path(const std::string& path);
};

} // namespace sentinel

#endif /* SENTINEL_SCOPE_GUARD_HPP */
