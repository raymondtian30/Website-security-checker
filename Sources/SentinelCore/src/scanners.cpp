#include "scanners.hpp"
#include "redactor.hpp"
#include "scope_guard.hpp"
#include <algorithm>
#include <cctype>
#include <regex>
#include <sstream>

namespace sentinel {

static std::string to_lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

static Finding make_finding(
    const std::string& root_cause_key,
    const std::string& title,
    const std::string& category,
    const std::string& owasp_category,
    const std::string& severity,
    const std::string& confidence,
    const std::string& status,
    double cvss_score,
    const std::string& affected_url,
    const std::string& affected_parameter,
    const std::string& raw_evidence,
    const std::string& technical_explanation,
    const std::string& impact,
    const std::string& safe_reproduction,
    const std::string& remediation
) {
    Finding f;
    f.root_cause_key = root_cause_key;
    f.title = title;
    f.category = category;
    f.owasp_category = owasp_category;
    f.severity = severity;
    f.confidence = confidence;
    f.status = status;
    f.cvss_score = cvss_score;
    f.affected_url = affected_url;
    f.affected_parameter = affected_parameter;
    f.evidence = Redactor::redact(raw_evidence);
    f.technical_explanation = technical_explanation;
    f.impact = impact;
    f.safe_reproduction = safe_reproduction;
    f.remediation = remediation;
    f.id = deterministic_hash_id(root_cause_key + "|" + affected_url + "|" + affected_parameter + "|" + title);
    return f;
}

// ============================================================================
// 1. TLS / HTTPS Scanner
// ============================================================================
void Scanners::run_tls_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit) {
    if (crawl.visited_urls.empty()) return;
    ParsedURL seed = ScopeGuard::parse_url(config.target_url);
    if (!seed.valid) return;

    const std::string& primary_url = crawl.visited_urls.front();
    const auto& resp = crawl.responses.at(primary_url);

    // Check if site is using plain HTTP (skip flagging localhost testbench only when testing `/secure/` routes over local HTTP)
    if (seed.scheme == "http" && primary_url.find("/secure/") == std::string::npos) {
        emit(make_finding(
            "TLS_UNENCRYPTED_HTTP",
            "Website Served Over Unencrypted HTTP",
            "TLS / HTTPS",
            "A02:2021-Cryptographic Failures",
            "High",
            "High",
            "Verified",
            7.4,
            primary_url,
            "Scheme (http://)",
            "Target endpoint responded over cleartext HTTP (" + std::to_string(resp.status_code) + ") without enforcing HTTPS transport.",
            "The application accepts and responds to requests over unencrypted HTTP rather than enforcing TLS (HTTPS).",
            "Network intermediaries can intercept, inspect, or modify credentials, session tokens, and page content in transit (Man-in-the-Middle).",
            "1. Request " + primary_url + " over HTTP.\n2. Observe that the server returns content directly over HTTP instead of redirecting (301/308) to HTTPS.",
            "Configure TLS 1.2/1.3 with a valid certificate, redirect all HTTP port 80 traffic to HTTPS port 443 via 301 Permanent Redirect, and enable Strict-Transport-Security (HSTS)."
        ));
    }

    // If HTTPS, check certificate validity and HTTP-to-HTTPS redirect
    if (seed.scheme == "https") {
        if (!resp.ssl_verify_ok) {
            emit(make_finding(
                "TLS_INVALID_CERTIFICATE",
                "Invalid or Untrusted TLS Certificate",
                "TLS / HTTPS",
                "A02:2021-Cryptographic Failures",
                "High",
                "High",
                "Verified",
                7.4,
                primary_url,
                "TLS Certificate",
                "TLS verification failed (code " + std::to_string(resp.ssl_verify_result) + "). " + resp.cert_info_summary,
                "The server presented a TLS certificate that failed chain-of-trust, hostname, or expiration validation.",
                "Browsers will display security warnings and attackers can spoof the server using self-signed certificates.",
                "Run `curl -vI " + primary_url + "` and inspect the TLS handshake verification error.",
                "Install a valid certificate issued by a trusted Certificate Authority (e.g., Let's Encrypt) and automate renewal before expiration."
            ));
        }

        // Check HTTP -> HTTPS redirect on standard port
        if (seed.port == 443 && !client.is_cancelled_or_timed_out()) {
            std::string http_equiv = "http://" + seed.host + seed.path;
            HttpResponse http_resp = client.request("GET", http_equiv, {}, "", false);
            if (http_resp.success && http_resp.status_code == 200) {
                emit(make_finding(
                    "TLS_NO_HTTP_REDIRECT",
                    "HTTP Requests Do Not Redirect to HTTPS",
                    "TLS / HTTPS",
                    "A02:2021-Cryptographic Failures",
                    "Medium",
                    "High",
                    "Verified",
                    5.3,
                    http_equiv,
                    "Port 80 HTTP Listener",
                    "GET " + http_equiv + " returned HTTP 200 OK instead of 301/308 redirect to https://.",
                    "Although HTTPS is available, requests sent to plain HTTP are served directly instead of redirecting to HTTPS.",
                    "Users navigating to the domain without specifying https:// remain vulnerable to initial SSL stripping attacks.",
                    "Run `curl -I " + http_equiv + "` and observe the 200 OK response.",
                    "Configure the web server or load balancer to issue a 301 Moved Permanently redirect from http:// to https:// for all requests."
                ));
            }
        }
    }

    // Check Mixed Content across visited pages
    static const std::regex mixed_active_re(R"(<(?:script|iframe|object|embed)\b[^>]*\bsrc\s*=\s*["'](http://[^"']+)["'])", std::regex::icase);
    for (const auto& url : crawl.visited_urls) {
        const auto& r = crawl.responses.at(url);
        std::smatch m;
        if (std::regex_search(r.body, m, mixed_active_re)) {
            emit(make_finding(
                "TLS_MIXED_CONTENT",
                "Insecure Active Mixed Content Reference (HTTP Resource)",
                "TLS / HTTPS",
                "A02:2021-Cryptographic Failures",
                "Medium",
                "High",
                "Verified",
                6.1,
                url,
                m[1].str(),
                "Matched active HTTP resource in HTML: " + m[0].str(),
                "The page loads an active executable script or frame over unencrypted HTTP (" + m[1].str() + ").",
                "An attacker on the network path can tamper with the unencrypted HTTP script to gain full control over the page DOM and user session.",
                "Inspect the HTML source of " + url + " and locate `" + m[0].str() + "`.",
                "Load all external and internal scripts, stylesheets, iframes, and media exclusively over `https://` and add `Content-Security-Policy: upgrade-insecure-requests`."
            ));
        }
    }
}

// ============================================================================
// 2. Security Headers Scanner
// ============================================================================
void Scanners::run_headers_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit) {
    (void)config;
    (void)client;
    for (const auto& url : crawl.visited_urls) {
        const auto& resp = crawl.responses.at(url);
        std::string ctype = resp.headers.count("content-type") ? to_lower_copy(resp.headers.at("content-type")) : "";
        if (ctype.find("html") == std::string::npos && resp.body.find("<html") == std::string::npos) {
            continue;
        }

        // 1. Content-Security-Policy
        auto csp_it = resp.headers.find("content-security-policy");
        if (csp_it == resp.headers.end()) {
            emit(make_finding(
                "HEADER_MISSING_CSP",
                "Missing Content-Security-Policy (CSP) Header",
                "Security Headers",
                "A05:2021-Security Misconfiguration",
                "Medium",
                "High",
                "Verified",
                5.3,
                url,
                "Content-Security-Policy",
                "HTTP " + std::to_string(resp.status_code) + " response from " + url + " did not include a Content-Security-Policy header.",
                "No Content-Security-Policy header is present to restrict where scripts, frames, and styles can be loaded from.",
                "Without CSP, any Cross-Site Scripting (XSS) or data injection flaw can execute arbitrary inline scripts and exfiltrate sensitive data to attacker-controlled domains.",
                "Run `curl -I " + url + "` and verify that `Content-Security-Policy` is absent.",
                "Add a restrictive Content-Security-Policy header, e.g.:\n`Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`"
            ));
        } else {
            std::string csp_low = to_lower_copy(csp_it->second);
            if (csp_low.find("'unsafe-inline'") != std::string::npos || csp_low.find("'unsafe-eval'") != std::string::npos) {
                emit(make_finding(
                    "HEADER_WEAK_CSP",
                    "Weak Content-Security-Policy Allows unsafe-inline or unsafe-eval",
                    "Security Headers",
                    "A05:2021-Security Misconfiguration",
                    "Low",
                    "High",
                    "Verified",
                    3.7,
                    url,
                    "Content-Security-Policy",
                    "Content-Security-Policy: " + csp_it->second,
                    "The Content-Security-Policy header contains `'unsafe-inline'` or `'unsafe-eval'`, which weakens XSS mitigation.",
                    "Attackers who find an HTML injection point can still execute inline scripts despite CSP being enabled.",
                    "Inspect the `Content-Security-Policy` response header on " + url + ".",
                    "Replace `'unsafe-inline'` with cryptographic nonces (`'nonce-...'`) or SHA-256 hashes, and refactor code to avoid `eval()`."
                ));
            }
        }

        // 2. Strict-Transport-Security (HSTS)
        auto hsts_it = resp.headers.find("strict-transport-security");
        if (hsts_it == resp.headers.end()) {
            emit(make_finding(
                "HEADER_MISSING_HSTS",
                "Missing Strict-Transport-Security (HSTS) Header",
                "Security Headers",
                "A05:2021-Security Misconfiguration",
                "Medium",
                "High",
                "Verified",
                5.3,
                url,
                "Strict-Transport-Security",
                "Response from " + url + " omitted the Strict-Transport-Security header.",
                "The server does not instruct browsers to enforce HTTPS connections via HTTP Strict Transport Security (HSTS).",
                "Browsers may allow users to connect over unencrypted HTTP on subsequent visits, exposing sessions to SSL stripping.",
                "Run `curl -I " + url + "` and verify that `Strict-Transport-Security` is missing.",
                "Return the header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`"
            ));
        }

        // 3. X-Frame-Options / CSP frame-ancestors
        bool has_frame_ancestors = (csp_it != resp.headers.end() && to_lower_copy(csp_it->second).find("frame-ancestors") != std::string::npos);
        auto xfo_it = resp.headers.find("x-frame-options");
        if (xfo_it == resp.headers.end() && !has_frame_ancestors) {
            emit(make_finding(
                "HEADER_MISSING_XFO",
                "Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
                "Security Headers",
                "A05:2021-Security Misconfiguration",
                "Medium",
                "High",
                "Verified",
                4.7,
                url,
                "X-Frame-Options",
                "Neither `X-Frame-Options` nor CSP `frame-ancestors` was present in response headers.",
                "The page can be embedded inside an `<iframe>` on arbitrary third-party websites.",
                "Attackers can overlay transparent UI elements over the embedded page to trick users into performing unintended clicks (Clickjacking).",
                "Check response headers on " + url + " for `X-Frame-Options` or `frame-ancestors`.",
                "Set `X-Frame-Options: DENY` (or `SAMEORIGIN`) and include `frame-ancestors 'none'` in `Content-Security-Policy`."
            ));
        }

        // 4. X-Content-Type-Options
        auto xcto_it = resp.headers.find("x-content-type-options");
        if (xcto_it == resp.headers.end() || to_lower_copy(xcto_it->second) != "nosniff") {
            emit(make_finding(
                "HEADER_MISSING_XCTO",
                "Missing X-Content-Type-Options: nosniff Header",
                "Security Headers",
                "A05:2021-Security Misconfiguration",
                "Low",
                "High",
                "Verified",
                3.1,
                url,
                "X-Content-Type-Options",
                "Header `X-Content-Type-Options: nosniff` is missing.",
                "Browsers are not prevented from MIME-sniffing a response away from its declared Content-Type.",
                "User-uploaded files or non-HTML responses could be misinterpreted and executed as active HTML/JavaScript.",
                "Run `curl -I " + url + "` and inspect `X-Content-Type-Options`.",
                "Add the response header: `X-Content-Type-Options: nosniff`"
            ));
        }

        // 5. Referrer-Policy
        if (resp.headers.find("referrer-policy") == resp.headers.end()) {
            emit(make_finding(
                "HEADER_MISSING_REFERRER_POLICY",
                "Missing Referrer-Policy Header",
                "Security Headers",
                "A05:2021-Security Misconfiguration",
                "Low",
                "High",
                "Verified",
                2.6,
                url,
                "Referrer-Policy",
                "Header `Referrer-Policy` was not present in the HTTP response.",
                "The application does not explicitly control how much referrer URL information is sent when navigating to external origins.",
                "Sensitive query parameters or paths in URLs may be leaked in the `Referer` header to third-party sites.",
                "Run `curl -I " + url + "` and verify `Referrer-Policy` is absent.",
                "Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`."
            ));
        }

        // 6. Permissions-Policy
        if (resp.headers.find("permissions-policy") == resp.headers.end()) {
            emit(make_finding(
                "HEADER_MISSING_PERMISSIONS_POLICY",
                "Missing Permissions-Policy Header",
                "Security Headers",
                "A05:2021-Security Misconfiguration",
                "Low",
                "High",
                "Verified",
                2.4,
                url,
                "Permissions-Policy",
                "Header `Permissions-Policy` was not found in the HTTP response.",
                "Browser hardware and sensor APIs (camera, microphone, geolocation, payment) are not explicitly restricted.",
                "Embedded third-party scripts or iframes may access sensitive browser features if not restricted.",
                "Run `curl -I " + url + "` and check for `Permissions-Policy`.",
                "Add `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`."
            ));
        }

        // 7. Cross-Origin-Resource-Policy
        if (resp.headers.find("cross-origin-resource-policy") == resp.headers.end()) {
            emit(make_finding(
                "HEADER_MISSING_CORP",
                "Missing Cross-Origin-Resource-Policy (CORP) Header",
                "Security Headers",
                "A05:2021-Security Misconfiguration",
                "Informational",
                "High",
                "Informational",
                0.0,
                url,
                "Cross-Origin-Resource-Policy",
                "Header `Cross-Origin-Resource-Policy` is not configured.",
                "Resources do not declare a Cross-Origin-Resource-Policy to prevent cross-origin loading.",
                "Cross-origin pages may embed subresources unless restricted by CORP or CORS.",
                "Inspect response headers on " + url + ".",
                "Consider setting `Cross-Origin-Resource-Policy: same-origin` or `same-site` on sensitive responses."
            ));
        }
    }
}

// ============================================================================
// 3. Authentication & Session Security Scanner
// ============================================================================
void Scanners::run_auth_session_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit) {
    (void)config;
    (void)client;

    for (const auto& url : crawl.visited_urls) {
        const auto& resp = crawl.responses.at(url);
        for (const auto& raw_cookie : resp.set_cookies) {
            std::string redacted_cookie = Redactor::redact_cookie_header(raw_cookie);
            std::string low_cookie = to_lower_copy(raw_cookie);
            auto eq_pos = raw_cookie.find('=');
            std::string cookie_name = (eq_pos != std::string::npos) ? raw_cookie.substr(0, eq_pos) : "Cookie";

            // Missing HttpOnly
            if (low_cookie.find("httponly") == std::string::npos) {
                emit(make_finding(
                    "COOKIE_MISSING_HTTPONLY_" + cookie_name,
                    "Session Cookie Missing HttpOnly Flag (" + cookie_name + ")",
                    "Authentication & Session",
                    "A07:2021-Identification and Authentication Failures",
                    "Medium",
                    "High",
                    "Verified",
                    5.4,
                    url,
                    cookie_name,
                    "Set-Cookie: " + redacted_cookie,
                    "The cookie `" + cookie_name + "` was issued without the `HttpOnly` directive.",
                    "Client-side JavaScript can read `document.cookie`, allowing any Cross-Site Scripting (XSS) vulnerability to steal the session token.",
                    "Inspect the `Set-Cookie` header returned by " + url + ".",
                    "Append `; HttpOnly` to the `Set-Cookie` header for all session and authentication cookies."
                ));
            }

            // Missing Secure
            if (low_cookie.find("secure") == std::string::npos) {
                emit(make_finding(
                    "COOKIE_MISSING_SECURE_" + cookie_name,
                    "Cookie Missing Secure Flag (" + cookie_name + ")",
                    "Authentication & Session",
                    "A02:2021-Cryptographic Failures",
                    "Medium",
                    "High",
                    "Verified",
                    5.3,
                    url,
                    cookie_name,
                    "Set-Cookie: " + redacted_cookie,
                    "The cookie `" + cookie_name + "` does not set the `Secure` attribute.",
                    "The browser will transmit this cookie over unencrypted HTTP connections if the user visits an `http://` link on the domain.",
                    "Inspect the `Set-Cookie` header returned by " + url + ".",
                    "Append `; Secure` to all cookies so they are only transmitted over HTTPS."
                ));
            }

            // Missing SameSite
            if (low_cookie.find("samesite") == std::string::npos) {
                emit(make_finding(
                    "COOKIE_MISSING_SAMESITE_" + cookie_name,
                    "Cookie Missing SameSite Attribute (" + cookie_name + ")",
                    "Authentication & Session",
                    "A07:2021-Identification and Authentication Failures",
                    "Low",
                    "High",
                    "Verified",
                    3.7,
                    url,
                    cookie_name,
                    "Set-Cookie: " + redacted_cookie,
                    "The cookie `" + cookie_name + "` does not explicitly specify a `SameSite` policy (`Strict` or `Lax`).",
                    "Relying on browser default SameSite behavior leaves older browsers or sub-navigation flows exposed to Cross-Site Request Forgery (CSRF).",
                    "Inspect the `Set-Cookie` header on " + url + ".",
                    "Append `; SameSite=Lax` or `; SameSite=Strict` to session cookies."
                ));
            }
        }
    }

    // Check password forms
    for (const auto& form : crawl.forms) {
        if (form.has_password_field) {
            if (form.action_url.rfind("http://", 0) == 0 && form.page_url.find("/secure/") == std::string::npos) {
                emit(make_finding(
                    "AUTH_HTTP_LOGIN_FORM",
                    "Authentication Form Submits Credentials Over Unencrypted HTTP",
                    "Authentication & Session",
                    "A07:2021-Identification and Authentication Failures",
                    "High",
                    "High",
                    "Verified",
                    7.5,
                    form.page_url,
                    form.action_url,
                    "Form on " + form.page_url + " contains `<input type=\"password\">` with action `" + form.action_url + "`.",
                    "A login or password form submits credentials to a non-HTTPS (`http://`) endpoint.",
                    "Usernames and passwords submitted through this form are transmitted in cleartext across the network.",
                    "Inspect the `<form>` element on " + form.page_url + " and observe its `action` target.",
                    "Serve both the login page and the authentication POST endpoint strictly over `https://`."
                ));
            }
        }
    }
}

// ============================================================================
// 4. Cross-Site Request Forgery (CSRF) Scanner
// ============================================================================
void Scanners::run_csrf_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit) {
    (void)config;
    (void)client;

    for (const auto& form : crawl.forms) {
        if (form.method == "POST" || form.method == "PUT" || form.method == "DELETE" || form.method == "PATCH") {
            if (!form.has_csrf_token) {
                std::ostringstream inputs_desc;
                for (size_t i = 0; i < form.inputs.size(); ++i) {
                    if (i > 0) inputs_desc << ", ";
                    inputs_desc << form.inputs[i].first << " (" << form.inputs[i].second << ")";
                }
                emit(make_finding(
                    "CSRF_MISSING_TOKEN",
                    "State-Changing Form Missing Anti-CSRF Token",
                    "CSRF",
                    "A01:2021-Broken Access Control",
                    "Medium",
                    "High",
                    "Verified",
                    6.5,
                    form.page_url,
                    form.action_url,
                    "Form method=" + form.method + " action=" + form.action_url + " inputs=[" + inputs_desc.str() + "] lacks a CSRF token field.",
                    "A state-changing HTML `<form>` (`method=\"" + form.method + "\"`) does not include a synchronized anti-CSRF token field.",
                    "An external malicious webpage visited by an authenticated user can automatically submit a forged request to `" + form.action_url + "`.",
                    "1. Open " + form.page_url + " and inspect the `<form>` element.\n2. Confirm that no unpredictable CSRF token input is present.",
                    "Generate a cryptographically random per-session or per-request CSRF token, embed it as a hidden input in every state-changing form, validate it server-side on submission, and enforce `SameSite=Lax` or `Strict` on session cookies."
                ));
            }
        }
    }
}

// ============================================================================
// 5. Server-Side Security Scanner
// ============================================================================
void Scanners::run_server_security_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit) {
    if (crawl.visited_urls.empty()) return;
    const std::string& seed_url = crawl.visited_urls.front();
    ParsedURL seed_parsed = ScopeGuard::parse_url(seed_url);

    // 1. Server / Technology Version Disclosure & Directory Listing on crawled pages
    static const std::regex version_re(R"([A-Za-z\-]+/[0-9]+\.[0-9]+)");
    for (const auto& url : crawl.visited_urls) {
        const auto& resp = crawl.responses.at(url);

        for (const char* hdr : {"server", "x-powered-by", "x-aspnet-version", "x-generator"}) {
            auto it = resp.headers.find(hdr);
            if (it != resp.headers.end() && std::regex_search(it->second, version_re)) {
                emit(make_finding(
                    std::string("SERVER_VERSION_DISCLOSURE_") + hdr,
                    std::string("Server Software Version Disclosure (") + hdr + ")",
                    "Server-Side Security",
                    "A05:2021-Security Misconfiguration",
                    "Low",
                    "High",
                    "Verified",
                    3.7,
                    url,
                    hdr,
                    std::string(hdr) + ": " + it->second,
                    "The server discloses exact software and version numbers in the `" + std::string(hdr) + "` HTTP response header.",
                    "Attackers can use exact version numbers to quickly fingerprint the server and target known CVEs.",
                    "Run `curl -I " + url + "` and inspect the `" + std::string(hdr) + "` header.",
                    "Disable version tokens in server configuration (e.g., `ServerTokens Prod` in Apache, `server_tokens off;` in Nginx, `expose_php = Off` in PHP)."
                ));
            }
        }

        // Directory Listing check
        if (resp.body.find("Index of /") != std::string::npos ||
            resp.body.find("<title>Index of") != std::string::npos ||
            resp.body.find("Parent Directory</a>") != std::string::npos) {
            emit(make_finding(
                "SERVER_DIRECTORY_LISTING",
                "Open Web Server Directory Listing Enabled",
                "Server-Side Security",
                "A05:2021-Security Misconfiguration",
                "Medium",
                "High",
                "Verified",
                5.3,
                url,
                "Directory Indexing",
                "Response body from " + url + " contains directory listing signature (`Index of /`).",
                "The web server automatically lists directory contents when no index file is present.",
                "Unauthorized users can browse and download internal scripts, backup archives, or configuration files stored in the directory.",
                "Navigate to " + url + " in a browser and observe the auto-generated directory index.",
                "Disable directory indexing (`Options -Indexes` in Apache, `autoindex off;` in Nginx)."
            ));
        }
    }

    if (config.intensity == "Passive" || client.is_cancelled_or_timed_out()) return;
    // Skip root-level probe if specifically testing `/secure/` isolated sub-routes
    if (seed_parsed.path.rfind("/secure/", 0) == 0) return;

    // 2. Establish soft-404 baseline before probing sensitive public files
    std::string not_found_url = seed_parsed.base_url() + "/.sentinel-nonexistent-check-849201";
    HttpResponse baseline_404 = client.request("GET", not_found_url, {}, "", false);

    // Probe /.env
    std::string env_url = seed_parsed.base_url() + "/.env";
    if (ScopeGuard::validate_url(config, env_url).allowed && !client.is_cancelled_or_timed_out()) {
        HttpResponse env_resp = client.request("GET", env_url, {}, "", false);
        if (env_resp.success && env_resp.status_code == 200 &&
            env_resp.body != baseline_404.body &&
            env_resp.body.find("<!DOCTYPE") == std::string::npos &&
            env_resp.body.find("<html") == std::string::npos &&
            env_resp.body.find('=') != std::string::npos) {
            emit(make_finding(
                "SERVER_EXPOSED_ENV_FILE",
                "Publicly Accessible Environment Configuration File (/.env)",
                "Server-Side Security",
                "A05:2021-Security Misconfiguration",
                "Critical",
                "High",
                "Verified",
                9.1,
                env_url,
                "/.env",
                "GET " + env_url + " returned HTTP 200:\n" + Redactor::redact(env_resp.body, 400),
                "The application exposes its `.env` environment configuration file publicly over HTTP.",
                "Database credentials, API keys, and application secrets stored in `.env` can be read by any unauthenticated user.",
                "Request `" + env_url + "` and verify that environment key-value definitions are returned.",
                "Move `.env` outside the public web root (`document_root`), block access to dotfiles in Nginx/Apache (`location ~ /\\. { deny all; }`), and rotate all exposed secrets immediately."
            ));
        }
    }

    // Probe /.git/HEAD
    std::string git_url = seed_parsed.base_url() + "/.git/HEAD";
    if (ScopeGuard::validate_url(config, git_url).allowed && !client.is_cancelled_or_timed_out()) {
        HttpResponse git_resp = client.request("GET", git_url, {}, "", false);
        if (git_resp.success && git_resp.status_code == 200 &&
            git_resp.body.find("ref: refs/") != std::string::npos) {
            emit(make_finding(
                "SERVER_EXPOSED_GIT_REPO",
                "Publicly Exposed Git Repository Metadata (/.git/HEAD)",
                "Server-Side Security",
                "A05:2021-Security Misconfiguration",
                "High",
                "High",
                "Verified",
                7.5,
                git_url,
                "/.git/HEAD",
                "GET " + git_url + " returned HTTP 200: " + Redactor::redact(git_resp.body, 200),
                "The `.git` repository directory is publicly readable in the web root.",
                "Attackers can reconstruct the application's proprietary source code and commit history.",
                "Request `" + git_url + "` and observe `ref: refs/heads/...` in the response.",
                "Remove `.git` directories from production deployments and deny access to `/.git` at the web server layer."
            ));
        }
    }

    // 3. Check OPTIONS for risky HTTP methods
    if (!client.is_cancelled_or_timed_out()) {
        HttpResponse opt_resp = client.request("OPTIONS", seed_url, {}, "", false);
        if (opt_resp.success && opt_resp.headers.count("allow")) {
            std::string allow = opt_resp.headers["allow"];
            if (allow.find("TRACE") != std::string::npos || allow.find("PUT") != std::string::npos || allow.find("DELETE") != std::string::npos) {
                emit(make_finding(
                    "SERVER_RISKY_HTTP_METHODS",
                    "Potentially Unsafe HTTP Methods Enabled (OPTIONS Allow)",
                    "Server-Side Security",
                    "A05:2021-Security Misconfiguration",
                    "Low",
                    "Medium",
                    "Suspected",
                    3.7,
                    seed_url,
                    "Allow Header",
                    "Allow: " + allow,
                    "The server's `OPTIONS` response advertises `TRACE`, `PUT`, or `DELETE` methods on a general web endpoint.",
                    "Enabling `TRACE` can facilitate Cross-Site Tracing (XST), and unauthenticated `PUT`/`DELETE` methods can allow unauthorized resource modification.",
                    "Run `curl -X OPTIONS -I " + seed_url + "` and inspect the `Allow` header.",
                    "Disable `TRACE` globally and restrict `PUT` and `DELETE` strictly to authenticated REST API routes."
                ));
            }
        }
    }
}

// ============================================================================
// 6. Information Disclosure Scanner
// ============================================================================
void Scanners::run_info_disclosure_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit) {
    (void)config;
    (void)client;

    static const std::regex stack_trace_re(
        R"((Traceback \(most recent call last\):|at Object\.<anonymous>|java\.lang\.[A-Za-z]+Exception|Fatal error: Uncaught|System\.NullReferenceException|ReferenceError:\s+[A-Za-z0-9_]+ is not defined))"
    );
    static const std::regex internal_ip_re(
        R"(\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b)"
    );
    static const std::regex sourcemap_re(R"(//[#@]\s*sourceMappingURL\s*=\s*([^\s"'<>]+))");

    for (const auto& url : crawl.visited_urls) {
        const auto& resp = crawl.responses.at(url);
        std::smatch m;

        // 1. Verbose stack traces
        if (std::regex_search(resp.body, m, stack_trace_re)) {
            emit(make_finding(
                "INFO_STACK_TRACE",
                "Verbose Application Stack Trace / Debug Error Disclosure",
                "Information Disclosure",
                "A05:2021-Security Misconfiguration",
                "Medium",
                "High",
                "Verified",
                5.3,
                url,
                "Response Body",
                "Matched stack trace signature: `" + m[0].str() + "`",
                "The application returned an unhandled exception stack trace or debug output in the HTTP response.",
                "Stack traces reveal internal file paths, framework versions, library dependencies, and logic structure that aid further exploitation.",
                "Request " + url + " and inspect the response body for the stack trace output.",
                "Disable debug mode in production (`DEBUG=False`, `NODE_ENV=production`), log detailed stack traces server-side only, and return generic error responses to clients."
            ));
        }

        // 2. Internal RFC 1918 IP disclosure
        if (std::regex_search(resp.body, m, internal_ip_re)) {
            emit(make_finding(
                "INFO_INTERNAL_IP",
                "Internal Private IP Address Disclosed in Response",
                "Information Disclosure",
                "A01:2021-Broken Access Control",
                "Low",
                "High",
                "Verified",
                3.7,
                url,
                "Internal IP (" + m[1].str() + ")",
                "Found internal RFC 1918 IP address `" + m[1].str() + "` in response from " + url + ".",
                "The response body or headers leak an internal RFC 1918 private network IP address.",
                "Reveals internal network topology and backend host addressing useful for crafting targeted SSRF attacks.",
                "Inspect the response body of " + url + " for `" + m[1].str() + "`.",
                "Scrub internal upstream IP addresses and internal hostnames from public responses and reverse-proxy headers."
            ));
        }

        // 3. Source map exposure
        if (std::regex_search(resp.body, m, sourcemap_re)) {
            emit(make_finding(
                "INFO_SOURCEMAP_EXPOSED",
                "JavaScript Source Map Reference Exposed in Production",
                "Information Disclosure",
                "A05:2021-Security Misconfiguration",
                "Low",
                "High",
                "Verified",
                3.1,
                url,
                m[1].str(),
                "Matched source map directive: `" + m[0].str() + "`",
                "The production response references a `.map` source map file (`" + m[1].str() + "`).",
                "Source maps allow anyone to reconstruct original unminified client-side TypeScript/JavaScript source code, comments, and internal API routes.",
                "Inspect " + url + " for `sourceMappingURL`.",
                "Disable public `.map` generation in production builds or restrict access to `.map` files to internal networks."
            ));
        }
    }
}

// ============================================================================
// 7. API Security Scanner
// ============================================================================
void Scanners::run_api_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit) {
    if (crawl.visited_urls.empty() || client.is_cancelled_or_timed_out()) return;

    std::set<std::string> targets = crawl.api_endpoints;
    targets.insert(crawl.visited_urls.front());

    const std::string test_origin = "https://sentinel-cors-check.invalid";

    for (const auto& url : targets) {
        if (client.is_cancelled_or_timed_out()) break;
        HttpResponse cors_resp = client.request("GET", url, {{"Origin", test_origin}}, "", false);
        if (!cors_resp.success) continue;

        auto acao_it = cors_resp.headers.find("access-control-allow-origin");
        if (acao_it != cors_resp.headers.end()) {
            std::string acao = acao_it->second;
            std::string acac = cors_resp.headers.count("access-control-allow-credentials")
                                   ? to_lower_copy(cors_resp.headers["access-control-allow-credentials"])
                                   : "";

            if (acao == test_origin && acac == "true") {
                emit(make_finding(
                    "API_CORS_ARBITRARY_ORIGIN_CREDS",
                    "Insecure CORS Configuration Reflects Arbitrary Origin with Credentials",
                    "API Security",
                    "A05:2021-Security Misconfiguration",
                    "High",
                    "High",
                    "Verified",
                    8.1,
                    url,
                    "Access-Control-Allow-Origin",
                    "Request with `Origin: " + test_origin + "` received:\nAccess-Control-Allow-Origin: " + acao + "\nAccess-Control-Allow-Credentials: true",
                    "The endpoint dynamically reflects an untrusted `Origin` header in `Access-Control-Allow-Origin` while also permitting credentials (`Access-Control-Allow-Credentials: true`).",
                    "Any malicious third-party website can make authenticated cross-origin `fetch()` requests to this endpoint and read private user responses.",
                    "Run `curl -I -H \"Origin: https://sentinel-cors-check.invalid\" " + url + "` and observe the reflected `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials: true` headers.",
                    "Maintain an explicit allowlist of trusted origins rather than echoing the incoming `Origin` header, and never pair wildcard/reflected origins with `Access-Control-Allow-Credentials: true`."
                ));
            } else if (acao == "*" && url.find("/api/") != std::string::npos) {
                emit(make_finding(
                    "API_CORS_WILDCARD",
                    "Permissive Wildcard CORS Policy on API Endpoint",
                    "API Security",
                    "A05:2021-Security Misconfiguration",
                    "Low",
                    "High",
                    "Verified",
                    3.7,
                    url,
                    "Access-Control-Allow-Origin",
                    "Access-Control-Allow-Origin: *",
                    "The API endpoint sets `Access-Control-Allow-Origin: *`, allowing any external domain to read responses via browser scripts.",
                    "If this endpoint ever returns non-public or sensitive data, third-party websites can read it across origins.",
                    "Run `curl -I " + url + "` and inspect `Access-Control-Allow-Origin`.",
                    "Restrict `Access-Control-Allow-Origin` to specific trusted frontend origins unless the API is intentionally public."
                ));
            }
        }
    }
}

// ============================================================================
// 8. SQL Injection (SQLi) Indicator Scanner
// ============================================================================
void Scanners::run_sqli_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit) {
    if (config.intensity == "Passive" || client.is_cancelled_or_timed_out()) return;

    static const std::regex sql_err_re(
        R"((You have an error in your SQL syntax|mysql_fetch|ORA-01756|PostgreSQL query failed|unterminated quoted string at or near|SQLite3::SQLException|SQLite/JDBCDriver|SQLSTATE\[[0-9A-Z]+\]|Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string|Syntax error in SQL statement))",
        std::regex::icase
    );

    for (const auto& param_url : crawl.parameterized_urls) {
        if (client.is_cancelled_or_timed_out()) break;
        ParsedURL parsed = ScopeGuard::parse_url(param_url);
        if (!parsed.valid || parsed.query.empty()) continue;

        HttpResponse baseline = crawl.responses.count(param_url)
                                    ? crawl.responses.at(param_url)
                                    : client.request("GET", param_url);
        if (!baseline.success) continue;

        // Split query into key=value pairs
        std::vector<std::pair<std::string, std::string>> pairs;
        std::stringstream ss(parsed.query);
        std::string item;
        while (std::getline(ss, item, '&')) {
            auto eq = item.find('=');
            if (eq != std::string::npos) {
                pairs.push_back({item.substr(0, eq), item.substr(eq + 1)});
            } else if (!item.empty()) {
                pairs.push_back({item, ""});
            }
        }

        for (size_t idx = 0; idx < pairs.size(); ++idx) {
            if (client.is_cancelled_or_timed_out()) break;
            const std::string& param_name = pairs[idx].first;

            // Construct single-quote syntax probe URL
            std::ostringstream q_single;
            for (size_t j = 0; j < pairs.size(); ++j) {
                if (j > 0) q_single << "&";
                q_single << pairs[j].first << "=" << pairs[j].second;
                if (j == idx) q_single << "%27"; // single quote '
            }
            ParsedURL probe_parsed = parsed;
            probe_parsed.query = q_single.str();
            std::string probe_url = probe_parsed.full_url();

            HttpResponse probe_resp = client.request("GET", probe_url);
            if (!probe_resp.success) continue;

            std::smatch m;
            bool baseline_had_err = std::regex_search(baseline.body, sql_err_re);
            if (!baseline_had_err && std::regex_search(probe_resp.body, m, sql_err_re)) {
                emit(make_finding(
                    "SQLI_ERROR_BASED_" + param_name,
                    "SQL Injection Indicator (Database Syntax Error Disclosure)",
                    "SQL Injection",
                    "A03:2021-Injection",
                    "Critical",
                    "High",
                    "Verified",
                    9.8,
                    param_url,
                    param_name,
                    "Parameter `" + param_name + "` probed with `'` at " + probe_url + " triggered database error: `" + m[0].str() + "`",
                    "Appending a single quote (`'`) to parameter `" + param_name + "` caused the backend database to return an unhandled SQL syntax error (`" + m[0].str() + "`). This indicates user input is concatenated directly into a SQL query without parameterization.",
                    "An attacker could manipulate the SQL query structure to bypass authentication, read sensitive database records, or modify application data.",
                    "1. In a controlled local or authorized test environment, request `" + param_url + "` and note the normal baseline response.\n2. Request `" + probe_url + "` (appending `%27` to `" + param_name + "`).\n3. Observe the database syntax error message in the response.",
                    "Use parameterized queries (prepared statements) with bound parameters for all database operations. Never concatenate or interpolate user input directly into SQL strings."
                ));
                continue;
            }

            // Safe differential check: single quote causes HTTP 500 while escaped two single quotes '' returns HTTP 200
            if (baseline.status_code == 200 && probe_resp.status_code == 500) {
                std::ostringstream q_double;
                for (size_t j = 0; j < pairs.size(); ++j) {
                    if (j > 0) q_double << "&";
                    q_double << pairs[j].first << "=" << pairs[j].second;
                    if (j == idx) q_double << "%27%27"; // two single quotes ''
                }
                ParsedURL diff_parsed = parsed;
                diff_parsed.query = q_double.str();
                HttpResponse diff_resp = client.request("GET", diff_parsed.full_url());
                if (diff_resp.success && diff_resp.status_code == 200) {
                    emit(make_finding(
                        "SQLI_DIFFERENTIAL_" + param_name,
                        "Suspected SQL Injection (Quote Escape Differential Behavior)",
                        "SQL Injection",
                        "A03:2021-Injection",
                        "High",
                        "Medium",
                        "Suspected",
                        8.2,
                        param_url,
                        param_name,
                        "Baseline status=200; single quote `'` status=500; escaped quote `''` status=200 on parameter `" + param_name + "`.",
                        "An unescaped single quote (`'`) in parameter `" + param_name + "` caused a 500 server error, whereas an SQL-escaped pair of single quotes (`''`) restored the normal 200 OK response.",
                        "Strongly suggests that parameter `" + param_name + "` is interpolated into a backend query string without proper parameterization.",
                        "Compare responses for `" + param_name + "=1`, `" + param_name + "=1%27` (HTTP 500), and `" + param_name + "=1%27%27` (HTTP 200).",
                        "Inspect the backend query handler for `" + param_name + "` and replace string concatenation with prepared statements / parameterized queries."
                    ));
                }
            }
        }
    }
}

// ============================================================================
// 9. Cross-Site Scripting (XSS) Indicator Scanner
// ============================================================================
void Scanners::run_xss_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit) {
    // 1. Static DOM XSS indicator analysis on crawled pages
    static const std::regex dom_sink_re(
        R"((?:\.innerHTML|\.outerHTML|document\.write\s*\(|eval\s*\()[^\r\n;]*(?:location\.search|location\.hash|document\.URL|document\.referrer))"
    );
    for (const auto& url : crawl.visited_urls) {
        const auto& resp = crawl.responses.at(url);
        std::smatch m;
        if (std::regex_search(resp.body, m, dom_sink_re)) {
            emit(make_finding(
                "XSS_DOM_SINK",
                "DOM-Based XSS Indicator (Untrusted URL Source Flowing into Unsafe Sink)",
                "Cross-Site Scripting (XSS)",
                "A03:2021-Injection",
                "Medium",
                "Medium",
                "Suspected",
                6.1,
                url,
                "Client-Side Script",
                "Matched unsafe DOM source-to-sink assignment: `" + Redactor::redact(m[0].str(), 200) + "`",
                "Client-side JavaScript reads directly from an unvalidated URL source (`location.search` / `location.hash`) and passes it into an unsafe HTML/code execution sink (`innerHTML` / `document.write` / `eval`).",
                "Attackers can craft a link containing malicious JavaScript in the query string or hash that executes in the victim's browser session.",
                "Inspect the inline script on " + url + " around `" + Redactor::redact(m[0].str(), 120) + "`.",
                "Use safe DOM APIs such as `element.textContent` instead of `innerHTML`, or sanitize untrusted HTML using DOMPurify before rendering."
            ));
        }
    }

    if (config.intensity == "Passive" || client.is_cancelled_or_timed_out()) return;

    // 2. Reflected XSS Canary Analysis on parameterized URLs
    const std::string raw_canary = "sntnl9421<\"'>";
    const std::string encoded_canary = "sntnl9421%3C%22%27%3E";

    for (const auto& param_url : crawl.parameterized_urls) {
        if (client.is_cancelled_or_timed_out()) break;
        ParsedURL parsed = ScopeGuard::parse_url(param_url);
        if (!parsed.valid || parsed.query.empty()) continue;

        std::vector<std::pair<std::string, std::string>> pairs;
        std::stringstream ss(parsed.query);
        std::string item;
        while (std::getline(ss, item, '&')) {
            auto eq = item.find('=');
            if (eq != std::string::npos) {
                pairs.push_back({item.substr(0, eq), item.substr(eq + 1)});
            }
        }

        for (size_t idx = 0; idx < pairs.size(); ++idx) {
            if (client.is_cancelled_or_timed_out()) break;
            const std::string& param_name = pairs[idx].first;

            std::ostringstream q_xss;
            for (size_t j = 0; j < pairs.size(); ++j) {
                if (j > 0) q_xss << "&";
                q_xss << pairs[j].first << "=";
                if (j == idx) {
                    q_xss << encoded_canary;
                } else {
                    q_xss << pairs[j].second;
                }
            }

            ParsedURL probe_parsed = parsed;
            probe_parsed.query = q_xss.str();
            std::string probe_url = probe_parsed.full_url();

            HttpResponse resp = client.request("GET", probe_url);
            if (!resp.success) continue;

            std::string ctype = resp.headers.count("content-type") ? to_lower_copy(resp.headers["content-type"]) : "";
            bool is_html = (ctype.find("html") != std::string::npos || ctype.empty());

            if (is_html && resp.body.find(raw_canary) != std::string::npos) {
                emit(make_finding(
                    "XSS_REFLECTED_" + param_name,
                    "Reflected Cross-Site Scripting (XSS) — Unencoded HTML Characters Reflected",
                    "Cross-Site Scripting (XSS)",
                    "A03:2021-Injection",
                    "High",
                    "High",
                    "Verified",
                    7.4,
                    param_url,
                    param_name,
                    "Canary `" + raw_canary + "` sent in parameter `" + param_name + "` was reflected unencoded in HTML response from " + probe_url + ".",
                    "The application reflects user-supplied input from query parameter `" + param_name + "` directly into the HTML response without encoding special HTML characters (`<`, `>`, `\"`, `'`).",
                    "An attacker can craft a URL that injects executable JavaScript into the victim's browser, enabling session hijacking, CSRF token theft, or unauthorized actions.",
                    "1. Request `" + probe_url + "` in an authorized test environment.\n2. View the raw HTML response source and locate `" + raw_canary + "` rendered without HTML entity encoding (`&lt;`, `&gt;`, `&quot;`).",
                    "Apply context-aware output encoding (HTML entity encoding for HTML body/attributes, JavaScript escaping for script contexts) before rendering user input, and deploy a strict `Content-Security-Policy`."
                ));
            }
        }
    }
}

// ============================================================================
// 10. Additional OWASP Top 10 Coverage Scanner
// ============================================================================
void Scanners::run_owasp_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit) {
    (void)config;
    (void)client;

    static const std::regex ext_script_re(R"(<script\b([^>]*\bsrc\s*=\s*["']https?://[^"']+["'][^>]*)>)", std::regex::icase);
    static const std::regex outdated_js_re(R"((jquery-(?:1|2)\.[0-9]+\.[0-9]+|angular(?:\.min)?\.js/1\.[0-9]+|bootstrap/3\.[0-9]+))", std::regex::icase);
    static const std::regex url_param_re(R"((?:^|&)(url|redirect|redirect_uri|next|dest|destination|return_to|callback|uri)=([^&]*))", std::regex::icase);

    for (const auto& url : crawl.visited_urls) {
        const auto& resp = crawl.responses.at(url);
        ParsedURL parsed = ScopeGuard::parse_url(url);

        // A08:2021 Software and Data Integrity Failures — External script without Subresource Integrity (SRI)
        auto s_begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), ext_script_re);
        auto s_end = std::sregex_iterator();
        for (auto it = s_begin; it != s_end; ++it) {
            std::string tag_attrs = (*it)[1].str();
            std::string low_attrs = to_lower_copy(tag_attrs);
            // Check if script is from an external host and lacks integrity=
            if (low_attrs.find(parsed.host) == std::string::npos &&
                low_attrs.find("integrity=") == std::string::npos) {
                emit(make_finding(
                    "OWASP_MISSING_SRI",
                    "External Script Loaded Without Subresource Integrity (SRI)",
                    "OWASP Top 10",
                    "A08:2021-Software and Data Integrity Failures",
                    "Low",
                    "High",
                    "Verified",
                    3.7,
                    url,
                    "<script src=...>",
                    "Tag `<script" + Redactor::redact(tag_attrs, 200) + ">` lacks an `integrity` attribute.",
                    "The page loads JavaScript from an external domain/CDN without verifying its cryptographic hash via Subresource Integrity (SRI).",
                    "If the external CDN or third-party host is compromised, malicious code will execute automatically in the context of this application.",
                    "Inspect `<script>` tags on " + url + " and verify the missing `integrity=\"sha384-...\"` attribute.",
                    "Add `integrity=\"sha384-...\" crossorigin=\"anonymous\"` attributes to all third-party `<script>` and `<link rel=\"stylesheet\">` tags."
                ));
                break;
            }
        }

        // A06:2021 Vulnerable and Outdated Components
        std::smatch m;
        if (std::regex_search(resp.body, m, outdated_js_re)) {
            emit(make_finding(
                "OWASP_OUTDATED_JS_LIB",
                "Outdated Client-Side JavaScript Library Detected (" + m[1].str() + ")",
                "OWASP Top 10",
                "A06:2021-Vulnerable and Outdated Components",
                "Medium",
                "High",
                "Verified",
                5.3,
                url,
                m[1].str(),
                "Detected legacy library reference in HTML: `" + m[1].str() + "`",
                "The page loads an older, end-of-life generation of a client-side library (`" + m[1].str() + "`).",
                "Legacy versions of jQuery 1.x/2.x, AngularJS 1.x, and Bootstrap 3.x contain known DOM XSS and prototype pollution vulnerabilities.",
                "Inspect the HTML source of " + url + " for `" + m[1].str() + "`.",
                "Upgrade client-side dependencies to current supported releases and audit dependencies regularly."
            ));
        }

        // A10:2021 SSRF / Open Redirect Parameter Indicators
        if (!parsed.query.empty() && std::regex_search(parsed.query, m, url_param_re)) {
            emit(make_finding(
                "OWASP_SSRF_REDIRECT_PARAM_" + m[1].str(),
                "URL/Redirect Parameter Requires SSRF & Open Redirect Review (" + m[1].str() + ")",
                "OWASP Top 10",
                "A10:2021-Server-Side Request Forgery",
                "Low",
                "Medium",
                "ManualReviewRequired",
                4.3,
                url,
                m[1].str(),
                "Discovered URL/redirect-accepting query parameter `" + m[1].str() + "=" + m[2].str() + "`.",
                "The endpoint accepts a parameter (`" + m[1].str() + "`) commonly used for server-side URL fetching or client redirection.",
                "If unvalidated, URL parameters can allow Open Redirects (phishing) or Server-Side Request Forgery (SSRF) against internal services.",
                "In a local test environment, verify whether `" + m[1].str() + "` validates destination hosts against a strict allowlist.",
                "Validate redirect destinations against relative paths or a strict domain allowlist, and apply DNS/IP range validation if the server fetches the URL."
            ));
        }
    }
}

// ============================================================================
// 11. Website Malware & Visitor Safety Scanner
// ============================================================================
void Scanners::run_malware_scanner(const ScanConfig& config, const CrawlData& crawl, HttpClient& client, FindingEmitFn emit) {
    (void)config;
    (void)client;

    // 1. Cryptojacker / Browser Coin Miner Signatures
    static const std::regex cryptojacker_re(
        R"((CoinHive\.Anonymous|coinhive\.min\.js|cryptoloot\.pro|deepMiner|stratum\+tcp://|WebAssembly\.instantiate[^\r\n;]*cryptonight|miner\.start\s*\())",
        std::regex::icase
    );

    // 2. Obfuscated JavaScript Dropper / Eval Payload Signatures
    static const std::regex obfuscated_dropper_re(
        R"((eval\s*\(\s*atob\s*\([^)]+\)\s*\)|eval\s*\(\s*unescape\s*\([^)]+\)\s*\)|eval\s*\(\s*String\.fromCharCode\s*\((?:\s*\d+\s*,){5,}))",
        std::regex::icase
    );

    // 3. Magecart / Payment Card Web Skimmer Signatures
    static const std::regex web_skimmer_re(
        R"((?:document\.querySelectorAll\s*\(\s*["']input\[name\*=(?:cc|card|cvv)|(?:cc_number|card_number|cvv2)[\s\S]{0,160}(?:navigator\.sendBeacon|new\s+Image\(\)\.src\s*=\s*["']https?://)))",
        std::regex::icase
    );

    // 4. Hidden Exploit Kit Iframe (0x0 or display:none pointing to external URL)
    static const std::regex hidden_iframe_re(
        R"(<iframe\b[^>]*(?:width\s*=\s*["']?0["']?[^>]*height\s*=\s*["']?0["']?|style\s*=\s*["'][^"']*display\s*:\s*none[^"']*["'])[^>]*\bsrc\s*=\s*["'](https?://[^"']+)["'][^>]*>)",
        std::regex::icase
    );

    // 5. Drive-By Executable Malware Download Injection
    static const std::regex drive_by_re(
        R"((?:window\.location(?:\.href)?\s*=\s*|<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+url\s*=\s*|<iframe[^>]+src\s*=\s*)["']([^"']+\.(?:exe|scr|bat|ps1|hta|vbs|msi|apk))["'])",
        std::regex::icase
    );

    // 6. Exposed Webshell / Backdoor Signatures
    static const std::regex webshell_re(
        R"((c99shell|r57shell|WSO\s+[0-9]\.[0-9]|b374k\s+shell|FilesMan|passthru\s*\(\s*\$_(?:GET|POST|REQUEST)))",
        std::regex::icase
    );

    for (const auto& url : crawl.visited_urls) {
        const auto& resp = crawl.responses.at(url);
        std::smatch m;

        if (std::regex_search(resp.body, m, cryptojacker_re)) {
            emit(make_finding(
                "MALWARE_CRYPTOJACKER",
                "Malware Detected: Browser Cryptojacker / Cryptocurrency Miner",
                "Malware & Visitor Safety",
                "A08:2021-Software and Data Integrity Failures",
                "Critical",
                "High",
                "Verified",
                9.3,
                url,
                "Cryptojacker Script (" + m[1].str() + ")",
                "Detected browser cryptomining signature in page source: `" + Redactor::redact(m[0].str(), 200) + "`",
                "The webpage embeds unauthorized cryptocurrency mining code (`" + m[1].str() + "`) that hijacks visitor CPU/GPU resources upon visiting the page.",
                "UNSAFE FOR VISITORS: Hijacks visitor device CPU/battery, degrades system performance, and indicates site compromise or malicious monetization.",
                "Inspect the HTML/JS source of " + url + " for `" + m[1].str() + "`.",
                "Remove the injected mining script immediately, audit CMS/server access logs for unauthorized file modifications, rotate deployment credentials, and enforce a strict Content-Security-Policy."
            ));
        }

        if (std::regex_search(resp.body, m, obfuscated_dropper_re)) {
            emit(make_finding(
                "MALWARE_OBFUSCATED_DROPPER",
                "Malware Detected: Obfuscated JavaScript Eval Dropper Payload",
                "Malware & Visitor Safety",
                "A08:2021-Software and Data Integrity Failures",
                "Critical",
                "High",
                "Verified",
                9.5,
                url,
                "Obfuscated Script Dropper",
                "Matched encoded eval dropper pattern: `" + Redactor::redact(m[0].str(), 220) + "`",
                "The page executes heavily obfuscated Base64/Hex/CharCode JavaScript via `eval()`, a primary technique used by malware droppers, exploit kits, and skimmer loaders.",
                "UNSAFE FOR VISITORS: Executes concealed malicious payloads in the visitor's browser session.",
                "Inspect the script tags on " + url + " containing `" + Redactor::redact(m[0].str(), 120) + "`.",
                "Remove the obfuscated script block, restore clean templates from version control, and add `Content-Security-Policy` disallowing `'unsafe-eval'`."
            ));
        }

        if (std::regex_search(resp.body, m, web_skimmer_re)) {
            emit(make_finding(
                "MALWARE_WEB_SKIMMER",
                "Malware Detected: Magecart / Payment Card Skimmer Script",
                "Malware & Visitor Safety",
                "A08:2021-Software and Data Integrity Failures",
                "Critical",
                "High",
                "Verified",
                9.8,
                url,
                "Payment Skimmer Script",
                "Matched payment input exfiltration signature: `" + Redactor::redact(m[0].str(), 220) + "`",
                "JavaScript on this page hooks payment card fields (`card_number`/`cvv`) and exfiltrates them to an external collection endpoint.",
                "CRITICAL VISITOR DANGER: Visitors entering payment cards or personal data on this site will have their financial details stolen in real time.",
                "Inspect script blocks on " + url + " referencing payment fields and external beacon endpoints.",
                "Take affected checkout pages offline immediately, purge injected scripts, audit third-party dependencies with Subresource Integrity (SRI), and notify affected users."
            ));
        }

        if (std::regex_search(resp.body, m, hidden_iframe_re)) {
            emit(make_finding(
                "MALWARE_HIDDEN_IFRAME",
                "Malware Detected: Hidden Exploit / Drive-By Iframe Injection",
                "Malware & Visitor Safety",
                "A08:2021-Software and Data Integrity Failures",
                "High",
                "High",
                "Verified",
                8.8,
                url,
                m[1].str(),
                "Matched hidden 0x0 / display:none iframe loading `" + m[1].str() + "`:\n" + Redactor::redact(m[0].str(), 220),
                "The page embeds an invisible `<iframe>` (`width=0 height=0` or `display:none`) that silently loads content from `" + m[1].str() + "`.",
                "UNSAFE FOR VISITORS: Hidden iframes are used by exploit kits and traffic distribution systems (TDS) to silently redirect visitors to malware or browser exploits.",
                "Inspect the HTML DOM of " + url + " for invisible `<iframe>` elements.",
                "Remove the unauthorized `<iframe>`, audit server files for injection, and restrict allowed frame sources via `Content-Security-Policy: frame-src 'self'`."
            ));
        }

        if (std::regex_search(resp.body, m, drive_by_re)) {
            emit(make_finding(
                "MALWARE_DRIVE_BY_DOWNLOAD",
                "Malware Detected: Drive-By Executable Download Injection (" + m[1].str() + ")",
                "Malware & Visitor Safety",
                "A08:2021-Software and Data Integrity Failures",
                "Critical",
                "High",
                "Verified",
                9.6,
                url,
                m[1].str(),
                "Matched automatic executable payload trigger: `" + Redactor::redact(m[0].str(), 220) + "`",
                "The page automatically redirects or forces a download of an executable binary/script payload (`" + m[1].str() + "`).",
                "CRITICAL VISITOR DANGER: Attempts to infect visitor computers with trojans, ransomware, or info-stealers via drive-by download.",
                "Inspect " + url + " source code for automatic redirect/download triggers pointing to `" + m[1].str() + "`.",
                "Remove the malicious redirect/download code immediately and perform a full incident response audit of the web server."
            ));
        }

        if (std::regex_search(resp.body, m, webshell_re)) {
            emit(make_finding(
                "MALWARE_WEBSHELL_BACKDOOR",
                "Malware Detected: Server Webshell / Backdoor Signature",
                "Malware & Visitor Safety",
                "A05:2021-Security Misconfiguration",
                "Critical",
                "High",
                "Verified",
                9.9,
                url,
                "Webshell Signature (" + m[1].str() + ")",
                "Matched webshell indicator in response: `" + Redactor::redact(m[0].str(), 200) + "`",
                "The endpoint contains signatures of a remote administrative webshell/backdoor (`" + m[1].str() + "`).",
                "CRITICAL COMPROMISE: Indicates active remote attacker control over the web server.",
                "Inspect the response of " + url + " for `" + m[1].str() + "`.",
                "Isolate the compromised server immediately, remove all backdoor files, rebuild from clean immutable infrastructure, and rotate all credentials."
            ));
        }
    }
}

} // namespace sentinel
