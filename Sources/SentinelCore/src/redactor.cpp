#include "redactor.hpp"
#include <regex>
#include <sstream>

namespace sentinel {

std::string Redactor::redact_cookie_header(const std::string& set_cookie_line) {
    // Format: name=value; Flag1; Flag2=val
    auto semi_pos = set_cookie_line.find(';');
    std::string first_part = (semi_pos == std::string::npos) ? set_cookie_line : set_cookie_line.substr(0, semi_pos);
    std::string rest = (semi_pos == std::string::npos) ? "" : set_cookie_line.substr(semi_pos);
    auto eq_pos = first_part.find('=');
    if (eq_pos == std::string::npos) {
        return set_cookie_line;
    }
    std::string name = first_part.substr(0, eq_pos);
    return name + "=[REDACTED]" + rest;
}

std::string Redactor::redact(const std::string& input, size_t max_length) {
    if (input.empty()) return "";

    std::string out = input;

    // 1. Redact PEM private keys
    static const std::regex pem_re(
        R"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----)",
        std::regex::icase
    );
    out = std::regex_replace(out, pem_re, "-----BEGIN PRIVATE KEY-----[REDACTED]-----END PRIVATE KEY-----");

    // 2. Redact Authorization headers (Bearer / Basic / Token)
    static const std::regex auth_re(
        R"((Authorization\s*:\s*(?:Bearer|Basic|Token)\s+)[^\r\n"'\s]+)",
        std::regex::icase
    );
    out = std::regex_replace(out, auth_re, "$1[REDACTED]");

    // 3. Redact common API key prefixes (OpenAI sk-, Google AIza, GitHub ghp_, AWS AKIA, Slack xoxb-)
    static const std::regex token_prefix_re(
        R"(\b(sk-[A-Za-z0-9_\-]{12,}|AIza[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9\-]{10,})\b)"
    );
    out = std::regex_replace(out, token_prefix_re, "[REDACTED_API_KEY]");

    // 4. Redact env/config key-value secrets (PASSWORD, SECRET, TOKEN, API_KEY, PRIVATE_KEY, DB_PASS, etc.)
    static const std::regex kv_secret_re(
        R"(((?:PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|CLIENT_SECRET|DB_PASS|AWS_SECRET_ACCESS_KEY)[A-Za-z0-9_]*\s*[:=]\s*["']?)([^"'\r\n\s,;]+)(["']?))",
        std::regex::icase
    );
    out = std::regex_replace(out, kv_secret_re, "$1[REDACTED]$3");

    // 5. Redact Set-Cookie or Cookie values
    static const std::regex cookie_val_re(
        R"(((?:session|sess|token|jwt|auth|sid|phpsessid|jsessionid|connect\.sid)[A-Za-z0-9_\-]*\s*=\s*)([^;\r\n"'\s]+))",
        std::regex::icase
    );
    out = std::regex_replace(out, cookie_val_re, "$1[REDACTED]");

    if (out.size() > max_length) {
        out = out.substr(0, max_length) + " ...[truncated]";
    }
    return out;
}

} // namespace sentinel
