# Security Considerations & Scanner Limitations

## 1. Authorization & Legal Use
Website Security Checker must only be used against domains and web applications that you own or have explicit written authorization to test. Every scan requires an explicit authorization confirmation that is recorded in the local SQLite audit log (`~/Library/Application Support/WebsiteSecurityChecker/sentinel_history.sqlite3`).

## 2. Server-Side SSRF, DNS Rebinding & Scope Protections
The C++ `ScopeGuard` enforces strict network boundaries before any socket connection is established:
- **Scheme Restriction**: Only `http://` and `https://` schemes are allowed.
- **Domain & Subdomain Scope**: Requests and redirects to third-party domains outside the configured target domain and allowed subdomain list are rejected.
- **Excluded Paths**: Normalized paths (resolving `/../` traversal segments) are checked against the excluded paths list (defaulting to `/logout`, `/signout`, `/delete`).
- **Private & Metadata IP Blocking**: Every hostname is resolved via `getaddrinfo()` and checked against:
  - Loopback (`127.0.0.0/8`, `::1`) — blocked unless Local Testbench Mode is explicitly enabled on ports `>= 1024`.
  - RFC 1918 Private Networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) — **always blocked**.
  - Cloud Metadata & Link-Local (`169.254.0.0/16`, `100.64.0.0/10`, `fe80::/10`) — **always blocked**.
  - Multicast, Broadcast, and Unspecified (`0.0.0.0/8`, `::`, `fc00::/7`, `224.0.0.0/4`) — **always blocked**.
- **DNS Rebinding Prevention**: Validated IP addresses are pinned per-request using `libcurl`'s `CURLOPT_RESOLVE`.
- **Manual Redirect Re-Validation**: Automatic redirects are disabled; every `3xx` `Location` target is re-validated through `ScopeGuard`.

## 3. Sensitive Data Redaction
Before any HTTP response snippet or header is saved to disk, displayed in the UI, or sent to an optional AI provider, `Redactor` masks:
- `Authorization` headers (`Bearer`, `Basic`, `Token`)
- Common API key formats (`sk-...`, `AIza...`, `ghp_...`, `AKIA...`, `xoxb-...`)
- Environment/config assignments (`PASSWORD=...`, `SECRET=...`, `API_KEY=...`, `PRIVATE_KEY=...`)
- PEM private key blocks
- Session cookie values (`Set-Cookie: sessionid=[REDACTED]; Secure; HttpOnly`)

## 4. Known Scanner Limitations
- **Non-Destructive Indicator Testing Only**: Sentinel does not perform destructive payloads, denial-of-service, credential brute-forcing, or data exfiltration.
- **JavaScript SPA Rendering**: The C++ crawler parses static HTML and script references; heavily obfuscated client-side single-page applications (SPAs) that construct routes exclusively at runtime in a headless browser may require manual endpoint seeding.
- **Business Logic & Multi-Factor Auth Flows**: Complex multi-step authenticated workflows require manual human review alongside automated scanning.
