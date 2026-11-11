#include "scope_guard.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

namespace sentinel {

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

std::string ScopeGuard::normalize_path(const std::string& raw_path) {
    if (raw_path.empty()) return "/";
    std::vector<std::string> segments;
    std::stringstream ss(raw_path);
    std::string item;
    bool trailing_slash = (raw_path.size() > 1 && raw_path.back() == '/');

    while (std::getline(ss, item, '/')) {
        if (item.empty() || item == ".") continue;
        if (item == "..") {
            if (!segments.empty()) segments.pop_back();
        } else {
            segments.push_back(item);
        }
    }

    std::string out = "/";
    for (size_t i = 0; i < segments.size(); ++i) {
        out += segments[i];
        if (i + 1 < segments.size()) out += "/";
    }
    if (trailing_slash && out.back() != '/') out += "/";
    return out;
}

ParsedURL ScopeGuard::parse_url(const std::string& raw_url) {
    ParsedURL res;
    std::string trimmed = raw_url;
    while (!trimmed.empty() && std::isspace((unsigned char)trimmed.front())) trimmed.erase(trimmed.begin());
    while (!trimmed.empty() && std::isspace((unsigned char)trimmed.back())) trimmed.pop_back();

    // Strip fragment
    auto hash_pos = trimmed.find('#');
    if (hash_pos != std::string::npos) {
        trimmed = trimmed.substr(0, hash_pos);
    }

    auto scheme_pos = trimmed.find("://");
    if (scheme_pos == std::string::npos) {
        return res;
    }

    res.scheme = to_lower(trimmed.substr(0, scheme_pos));
    if (res.scheme != "http" && res.scheme != "https") {
        return res;
    }

    std::string remainder = trimmed.substr(scheme_pos + 3);
    std::string authority;
    std::string path_and_query = "/";

    auto slash_pos = remainder.find('/');
    auto q_pos = remainder.find('?');
    if (slash_pos == std::string::npos && q_pos == std::string::npos) {
        authority = remainder;
    } else if (slash_pos != std::string::npos && (q_pos == std::string::npos || slash_pos < q_pos)) {
        authority = remainder.substr(0, slash_pos);
        path_and_query = remainder.substr(slash_pos);
    } else {
        authority = remainder.substr(0, q_pos);
        path_and_query = "/" + remainder.substr(q_pos);
    }

    // Disallow credentials in URL (user:pass@host)
    if (authority.find('@') != std::string::npos) {
        return res;
    }

    res.port = (res.scheme == "https") ? 443 : 80;

    // Handle IPv6 literal [::1]:8080 or standard host:port
    if (!authority.empty() && authority.front() == '[') {
        auto close_bracket = authority.find(']');
        if (close_bracket == std::string::npos) return res;
        res.host = to_lower(authority.substr(1, close_bracket - 1));
        if (close_bracket + 1 < authority.size()) {
            if (authority[close_bracket + 1] != ':') return res;
            try {
                res.port = std::stoi(authority.substr(close_bracket + 2));
            } catch (...) {
                return res;
            }
        }
    } else {
        auto colon_pos = authority.rfind(':');
        if (colon_pos != std::string::npos) {
            res.host = to_lower(authority.substr(0, colon_pos));
            try {
                res.port = std::stoi(authority.substr(colon_pos + 1));
            } catch (...) {
                return res;
            }
        } else {
            res.host = to_lower(authority);
        }
    }

    if (res.host.empty() || res.port <= 0 || res.port > 65535) {
        return res;
    }

    auto query_pos = path_and_query.find('?');
    if (query_pos != std::string::npos) {
        res.path = normalize_path(path_and_query.substr(0, query_pos));
        res.query = path_and_query.substr(query_pos + 1);
    } else {
        res.path = normalize_path(path_and_query);
    }

    res.valid = true;
    return res;
}

std::string ScopeGuard::resolve_relative_url(const ParsedURL& base, const std::string& href) {
    if (href.empty()) return "";
    if (href.rfind("javascript:", 0) == 0 || href.rfind("mailto:", 0) == 0 ||
        href.rfind("tel:", 0) == 0 || href.rfind("data:", 0) == 0 || href.front() == '#') {
        return "";
    }
    if (href.rfind("http://", 0) == 0 || href.rfind("https://", 0) == 0) {
        return href;
    }
    if (href.rfind("//", 0) == 0) {
        return base.scheme + ":" + href;
    }
    if (href.front() == '/') {
        return base.base_url() + href;
    }
    // Relative to current directory
    std::string dir = base.path;
    auto last_slash = dir.rfind('/');
    if (last_slash != std::string::npos) {
        dir = dir.substr(0, last_slash + 1);
    } else {
        dir = "/";
    }
    return base.base_url() + normalize_path(dir + href);
}

bool ScopeGuard::is_ipv4_forbidden(uint32_t ip, bool allow_loopback, std::string& reason) {
    uint8_t b0 = (ip >> 24) & 0xFF;
    uint8_t b1 = (ip >> 16) & 0xFF;
    uint8_t b2 = (ip >> 8) & 0xFF;
    uint8_t b3 = ip & 0xFF;

    // 0.0.0.0/8
    if (b0 == 0) {
        reason = "Blocked unspecified IP range (0.0.0.0/8)";
        return true;
    }
    // 127.0.0.0/8 Loopback
    if (b0 == 127) {
        if (!allow_loopback) {
            reason = "Blocked loopback address (127.0.0.0/8)";
            return true;
        }
        return false;
    }
    // 10.0.0.0/8 RFC 1918
    if (b0 == 10) {
        reason = "Blocked private internal network (10.0.0.0/8)";
        return true;
    }
    // 172.16.0.0/12 RFC 1918
    if (b0 == 172 && (b1 >= 16 && b1 <= 31)) {
        reason = "Blocked private internal network (172.16.0.0/12)";
        return true;
    }
    // 192.168.0.0/16 RFC 1918
    if (b0 == 192 && b1 == 168) {
        reason = "Blocked private internal network (192.168.0.0/16)";
        return true;
    }
    // 169.254.0.0/16 Link-local & Cloud Metadata (169.254.169.254)
    if (b0 == 169 && b1 == 254) {
        reason = "Blocked link-local / cloud metadata endpoint (169.254.0.0/16)";
        return true;
    }
    // Alibaba cloud metadata 100.100.100.200 & CGNAT 100.64.0.0/10
    if (b0 == 100 && (b1 >= 64 && b1 <= 127)) {
        reason = "Blocked shared/metadata network range (100.64.0.0/10)";
        return true;
    }
    // 192.0.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15
    if (b0 == 198 && (b1 == 18 || b1 == 19)) {
        reason = "Blocked benchmark network range (198.18.0.0/15)";
        return true;
    }
    // Multicast & Reserved >= 224.0.0.0
    if (b0 >= 224) {
        reason = "Blocked multicast/reserved IP range (224.0.0.0+)";
        return true;
    }
    (void)b2;
    (void)b3;
    return false;
}

bool ScopeGuard::is_ip_string_allowed(const std::string& ip_str, bool allow_loopback, std::string& reason) {
    struct in_addr addr4;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr4) == 1) {
        uint32_t host_ip = ntohl(addr4.s_addr);
        return !is_ipv4_forbidden(host_ip, allow_loopback, reason);
    }

    struct in6_addr addr6;
    if (inet_pton(AF_INET6, ip_str.c_str(), &addr6) == 1) {
        const uint8_t* b = addr6.s6_addr;
        // Unspecified ::
        bool all_zero = true;
        for (int i = 0; i < 16; ++i) {
            if (b[i] != 0) { all_zero = false; break; }
        }
        if (all_zero) {
            reason = "Blocked unspecified IPv6 address (::)";
            return false;
        }
        // Loopback ::1
        bool is_loopback6 = true;
        for (int i = 0; i < 15; ++i) {
            if (b[i] != 0) { is_loopback6 = false; break; }
        }
        if (is_loopback6 && b[15] == 1) {
            if (!allow_loopback) {
                reason = "Blocked IPv6 loopback address (::1)";
                return false;
            }
            return true;
        }
        // IPv4-mapped IPv6 ::ffff:a.b.c.d
        bool is_v4_mapped = true;
        for (int i = 0; i < 10; ++i) {
            if (b[i] != 0) { is_v4_mapped = false; break; }
        }
        if (is_v4_mapped && b[10] == 0xFF && b[11] == 0xFF) {
            uint32_t v4 = ((uint32_t)b[12] << 24) | ((uint32_t)b[13] << 16) |
                          ((uint32_t)b[14] << 8) | (uint32_t)b[15];
            return !is_ipv4_forbidden(v4, allow_loopback, reason);
        }
        // Unique Local fc00::/7
        if ((b[0] & 0xFE) == 0xFC) {
            reason = "Blocked IPv6 unique local address (fc00::/7)";
            return false;
        }
        // Link-Local fe80::/10
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) {
            reason = "Blocked IPv6 link-local address (fe80::/10)";
            return false;
        }
        // Multicast ff00::/8
        if (b[0] == 0xFF) {
            reason = "Blocked IPv6 multicast address (ff00::/8)";
            return false;
        }
        return true;
    }

    reason = "Invalid IP address format";
    return false;
}

ScopeValidationResult ScopeGuard::validate_url(const ScanConfig& config, const std::string& candidate_url) {
    ScopeValidationResult out;

    if (!config.authorized) {
        out.reason = "Authorization confirmation is required before scanning.";
        return out;
    }

    out.parsed = parse_url(candidate_url);
    if (!out.parsed.valid) {
        out.reason = "Invalid URL or unsupported scheme (only http and https are allowed).";
        return out;
    }

    // Block localhost by hostname unless local testbench is explicitly enabled on non-privileged port
    std::string host = out.parsed.host;
    if (host == "localhost" || host == "localhost.localdomain" ||
        (host.size() > 6 && host.substr(host.size() - 6) == ".local")) {
        if (!(config.allow_local_testbench && host == "localhost" && out.parsed.port >= 1024)) {
            out.reason = "Blocked localhost / .local hostname.";
            return out;
        }
    }

    // Determine primary target domain
    std::string primary_domain = to_lower(config.target_domain);
    if (primary_domain.empty()) {
        ParsedURL target_parsed = parse_url(config.target_url);
        primary_domain = target_parsed.host;
    } else if (primary_domain.find("://") != std::string::npos) {
        ParsedURL target_parsed = parse_url(primary_domain);
        primary_domain = target_parsed.host;
    }

    if (primary_domain.empty()) {
        out.reason = "Target domain is not configured.";
        return out;
    }

    // Check host scope
    bool host_in_scope = (host == primary_domain);
    if (!host_in_scope && config.include_subdomains) {
        std::string suffix = "." + primary_domain;
        if (host.size() > suffix.size() &&
            host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0) {
            host_in_scope = true;
        }
    }
    if (!host_in_scope) {
        for (const auto& sub : config.allowed_subdomains) {
            std::string clean_sub = to_lower(sub);
            if (!clean_sub.empty() && host == clean_sub) {
                host_in_scope = true;
                break;
            }
        }
    }

    if (!host_in_scope) {
        out.reason = "Host '" + host + "' is outside authorized scope ('" + primary_domain + "').";
        return out;
    }

    // Check excluded paths
    for (const auto& raw_excl : config.excluded_paths) {
        if (raw_excl.empty()) continue;
        std::string excl = normalize_path(raw_excl);
        if (excl.size() > 1 && excl.back() == '/') excl.pop_back();
        if (out.parsed.path == excl ||
            (out.parsed.path.size() > excl.size() &&
             out.parsed.path.compare(0, excl.size(), excl) == 0 &&
             out.parsed.path[excl.size()] == '/')) {
            out.reason = "Path '" + out.parsed.path + "' matches excluded path '" + raw_excl + "'.";
            return out;
        }
    }

    bool allow_loopback = (config.allow_local_testbench && out.parsed.port >= 1024);

    // Check if host is already a literal IP
    std::string ip_reason;
    struct in_addr dummy4;
    struct in6_addr dummy6;
    if (inet_pton(AF_INET, host.c_str(), &dummy4) == 1 ||
        inet_pton(AF_INET6, host.c_str(), &dummy6) == 1) {
        if (!is_ip_string_allowed(host, allow_loopback, ip_reason)) {
            out.reason = ip_reason;
            return out;
        }
        out.allowed = true;
        out.resolved_ip = host;
        out.reason = "Allowed";
        return out;
    }

    // Perform DNS resolution and inspect ALL returned IPv4/IPv6 addresses
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = nullptr;
    int err = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (err != 0 || !res) {
        out.reason = std::string("DNS resolution failed for host '") + host + "'";
        return out;
    }

    std::string first_valid_ip;
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        char ip_buf[INET6_ADDRSTRLEN] = {0};
        if (p->ai_family == AF_INET) {
            struct sockaddr_in* ipv4 = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
            inet_ntop(AF_INET, &(ipv4->sin_addr), ip_buf, sizeof(ip_buf));
        } else if (p->ai_family == AF_INET6) {
            struct sockaddr_in6* ipv6 = reinterpret_cast<struct sockaddr_in6*>(p->ai_addr);
            inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_buf, sizeof(ip_buf));
        } else {
            continue;
        }

        std::string resolved_str(ip_buf);
        if (!is_ip_string_allowed(resolved_str, allow_loopback, ip_reason)) {
            freeaddrinfo(res);
            out.reason = "DNS resolution for '" + host + "' returned forbidden IP " + resolved_str + ": " + ip_reason;
            return out;
        }
        if (first_valid_ip.empty()) {
            first_valid_ip = resolved_str;
        }
    }

    freeaddrinfo(res);

    if (first_valid_ip.empty()) {
        out.reason = "No valid IP addresses resolved for host '" + host + "'";
        return out;
    }

    out.allowed = true;
    out.resolved_ip = first_valid_ip;
    out.reason = "Allowed";
    return out;
}

} // namespace sentinel
