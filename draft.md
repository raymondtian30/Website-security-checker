# Website Security Checker ("Sentinel") — Comprehensive Implementation Plan

---

## 0. Repository & Mandatory Workflow Verification

### 0.1 Existing GitHub Repository Inspection (Section 1)
- **Local Working Directory**: `/Users/raymond/Desktop/Website-security-checker`
- **Remote Configuration**: `origin -> git@github.com:raymondtian30/Website-security-checker.git` (fetch & push verified)
- **Current Branch**: `main` (initial branch, no prior commits)
- **Existing Working Tree**: Only `.DS_Store` (untracked); no existing code to overwrite.

### 0.2 Mandatory Skill Availability Check (Section 18, Steps 1 & 6)
Before writing any code, the available skills in `<available_skills>` were inspected:
- `egm:brainstorm` — **Not available** in the runtime's `<available_skills>` catalog.
- `egm:draft` — **Not available** in the runtime's `<available_skills>` catalog.
- `superpowers:executeplan` — **Not available** in the runtime's `<available_skills>` catalog.

**Step 6 Fallback Protocol**:
In strict compliance with Section 18 Step 6, we explicitly note that these three skills are not installed in the harness environment, do not claim they were invoked, and execute an equivalent structured engineering workflow:
1. **Phase A (Brainstorm & Tradeoff Analysis)** — Section 1 of this document.
2. **Phase B (Detailed Architecture & Implementation Plan Draft)** — Sections 2–13 of this document.
3. **Phase C (Architecture & Security Review)** — Section 14 of this document.
4. **Phase D (Incremental Milestone Execution, Automated Verification, & Git Workflow)** — Section 15 of this document.

---

## 1. Structured Brainstorm & Technical Tradeoff Analysis

### 1.1 Product Vision & Core Value Proposition
Website Security Checker ("Sentinel") is a native macOS security auditing application built with **Swift & SwiftUI** for the desktop experience and **C++17/20** for the core security scanning engine. It allows authorized website owners and security engineers to:
1. Explicitly attest authorization and configure strict scope boundaries.
2. Execute non-destructive, rate-limited, scope-enforced vulnerability assessments.
3. Obtain high-signal findings with redacted technical evidence, CVSS scores, OWASP Top 10 (2021) mappings, and clear differentiation between **Verified**, **Suspected**, **Informational**, **Manual Review Required**, and **Incomplete** checks.
4. Receive a transparent 0–100 security score, letter grade (`A+` to `F`), and separate **Scan Coverage %** metric.
5. Investigate findings interactively with an **AI Security Analyst** that works both offline (via a deterministic context-correlating rule engine) and online (via macOS Keychain-secured OpenAI, Anthropic, or Gemini API keys).
6. Track historical security posture across scans, compare two scans side-by-side, and export executive/technical reports in **PDF**, **HTML**, and **JSON**.

### 1.2 Key Architectural Decisions

| Area | Alternatives Considered | Selected Design & Justification |
|---|---|---|
| **Build System & Packaging** | Xcode `.xcodeproj` only vs. Swift Package Manager (`Package.swift`) + `.app` bundler script | **`Package.swift` + `scripts/build-app.sh`**: Enables clean, reproducible CLI builds (`swift build`, `swift test`) while bundling a full native macOS `.app` (`WebsiteSecurityChecker.app`) with `Info.plist` and entitlements. |
| **Swift <-> C++ Communication** | Local socket daemon vs. Pure C ABI bridge (`sentinel_bridge.h`) linked directly into Swift | **In-process C ABI Bridge**: Eliminates IPC serialization overhead, zombie background processes, and local port collisions. Supports real-time progress callbacks, live finding streaming, atomic pause/resume, and instant cancellation. |
| **C++ HTTP & TLS Layer** | Third-party C++ libraries (Boost.Beast/cpr) vs. macOS System `libcurl` (`-lcurl`) | **System `libcurl` (`/usr/lib/libcurl.dylib`)**: Ships natively on every macOS system, requires zero external dependency downloads, exposes TLS certificate chains (`CURLINFO_CERTINFO`), protocol versions, timing metrics, and supports IP pinning (`CURLOPT_RESOLVE`) to defeat DNS rebinding. |
| **Database Persistence** | SwiftData vs. Native SQLite3 (`-lsqlite3`) | **SQLite3 Direct Persistence (`DatabaseManager.swift`)**: Zero macro or OS-version friction, deterministic relational schema, fast foreign-key cascade deletes, easy diff queries across historical scans, and full testability in CLI test runners. |
| **PDF Report Export** | External Chromium/wkhtmltopdf vs. Native macOS `PDFKit` / `CoreGraphics` / `NSPrintOperation` | **Native macOS CoreGraphics/PDFKit Renderer**: Generates crisp, multi-page vector PDFs directly in Swift with zero external binary dependencies. |

---

## 2. Project Structure & File Layout

Every file has a single, clear responsibility in accordance with Section 19 (Simplicity and Efficiency First):

```text
Website-security-checker/
├── Package.swift
├── draft.md
├── README.md
├── .gitignore
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SCORING.md
│   └── SECURITY_CONSIDERATIONS.md
├── scripts/
│   ├── build-app.sh                      # Builds release binary and packages WebsiteSecurityChecker.app
│   └── uninstall.sh                      # Removes app bundle, preferences, Keychain items, and SQLite DB
├── Sources/
│   ├── SentinelCore/                     # C++17 Modular Security Scanning Engine
│   │   ├── include/
│   │   │   └── sentinel_bridge.h         # C ABI exposed to Swift
│   │   ├── src/
│   │   │   ├── types.hpp                 # Internal C++ structs: ScanConfig, HttpResponse, Finding, Progress
│   │   │   ├── redactor.hpp / .cpp       # Redacts secrets, tokens, keys, PII before storing evidence
│   │   │   ├── scope_guard.hpp / .cpp    # URL parser, DNS resolver, private IP blocker, scope validator
│   │   │   ├── http_client.hpp / .cpp    # libcurl client, IP pinning, manual redirect validation, rate limiter
│   │   │   ├── crawler.hpp / .cpp        # In-scope HTML link, form, script, and API endpoint extractor
│   │   │   ├── scanners.hpp / .cpp       # Modular scanners (SQLi, XSS, Auth/Cookies, CSRF, Server, Headers, TLS, API, InfoDisclosure, OWASP)
│   │   │   ├── engine.hpp / .cpp         # Scan orchestrator, coverage tracker, pause/resume/cancel controller
│   │   │   └── sentinel_bridge.cpp       # C ABI implementation and JSON serialization for Swift bridge
│   ├── SentinelKit/                      # Swift Core Domain, Persistence, Scoring, AI, Reporting
│   │   ├── Models.swift                  # Codable models: ScanConfiguration, Finding, ScanRecord, AuditLogEntry, ScanComparison
│   │   ├── SecurityScorer.swift          # 0-100 scoring algorithm, root-cause deduplication, grade & coverage calculation
│   │   ├── ScannerBridge.swift           # Async/await Swift wrapper around sentinel_bridge C functions
│   │   ├── DatabaseManager.swift         # SQLite3 persistence for scans, findings, audit logs, resolved states
│   │   ├── AISecurityAnalyst.swift       # Offline deterministic analyst + Keychain-backed LLM integration (OpenAI/Anthropic/Gemini)
│   │   └── ReportGenerator.swift         # JSON, standalone HTML, and native multi-page PDF report generators
│   └── WebsiteSecurityChecker/           # Native macOS SwiftUI Application
│       ├── WebsiteSecurityCheckerApp.swift
│       ├── AppViewModel.swift            # @MainActor state orchestration, live scan telemetry, navigation
│       ├── Theme.swift                   # Dark-first cybersecurity color system, badges, reusable cards
│       ├── DashboardView.swift           # Score gauge, grade, coverage, severity breakdown, Swift Charts trends
│       ├── ScanConfigView.swift          # Target config, mandatory authorization attestation, live scan monitor
│       ├── FindingsView.swift            # Filterable/searchable findings list + expandable detail inspector
│       ├── InvestigationView.swift       # AI Security Analyst interactive walkthrough & safe validation guide
│       ├── HistoryComparisonView.swift   # Scan history table, side-by-side scan comparison, report export
│       └── SettingsAuditView.swift       # AI API key management (Keychain), scan defaults, immutable audit logs
└── Tests/
    └── SentinelTests/
        ├── LocalTestServer.swift         # Local HTTP server with deliberately vulnerable & secure routes
        └── SentinelEngineTests.swift     # Comprehensive tests for ScopeGuard, all scanners, Scorer, DB, Reports, Cancel
```

---

## 3. Authorization, Scope Enforcement & Server-Side Safety System (Section 3)

### 3.1 Authorization Gate & Audit Logging
1. Every scan requires an explicit `AuthorizationConfirmation`:
   - User must check **"I confirm that I own this target domain or have explicit written authorization to perform this security assessment."**
   - The confirmation, target domain, allowed subdomains, excluded paths, scan intensity, rate limit, and timestamp are written to an immutable SQLite `audit_logs` table **before** the C++ engine is invoked.
   - The C++ engine independently rejects any scan configuration where `authorized != true`.

### 3.2 Strict SSRF, DNS Rebinding & IP Range Protections (`ScopeGuard`)
The C++ `ScopeGuard` validates **every** URL (initial target, crawled links, and every HTTP `3xx` redirect location) before any network socket is opened:

1. **Scheme Validation**: Only `http://` and `https://` are permitted (`file://`, `ftp://`, `gopher://`, `dict://`, `ldap://`, `ws://` are rejected).
2. **Host & Subdomain Scope Validation**:
   - Extracts normalized lowercase host.
   - Must match `target_domain` exactly OR match an explicitly configured entry in `allowed_subdomains` (or be a subdomain of `target_domain` when `include_subdomains` is enabled).
   - Any third-party domain (e.g., `googleapis.com`, `cloudflare.com`, external CDNs) is rejected for active probing.
3. **Excluded Path Enforcement**:
   - Normalizes path traversal segments (`/a/../b` -> `/b`) and checks against `excluded_paths` (defaulting to `/logout`, `/signout`, `/delete`, `/admin/delete`).
4. **DNS Resolution & Private/Reserved IP Blocking**:
   - Calls `getaddrinfo()` and inspects **every** returned IPv4 (`AF_INET`) and IPv6 (`AF_INET6`) address.
   - Blocks the request if **any** resolved IP falls within:
     - **Loopback**: `127.0.0.0/8`, `::1`
     - **Unspecified / Current Network**: `0.0.0.0/8`, `::`
     - **RFC 1918 Private Networks**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
     - **Link-Local & Cloud Metadata Endpoints**: `169.254.0.0/16` (AWS/GCP/Azure `169.254.169.254`), `fe80::/10`, Alibaba Cloud `100.100.100.200`
     - **Carrier-Grade NAT (RFC 6598)**: `100.64.0.0/10`
     - **IPv6 Unique Local (ULA)**: `fc00::/7`
     - **IPv4-Mapped IPv6 Private/Loopback**: `::ffff:127.0.0.1`, `::ffff:10.x.x.x`, `::ffff:169.254.x.x`, etc.
     - **Multicast & Broadcast**: `224.0.0.0/4`, `255.255.255.255`, `ff00::/8`
   - *Local Testbench Exception*: An explicit `allow_local_testbench` boolean (off by default in production UI unless explicitly testing the built-in local test server on `127.0.0.1`) allows only `127.0.0.1` on non-privileged ports (`>= 1024`) while still blocking metadata IPs (`169.254.169.254`) and RFC 1918 LAN IPs (`10.x`, `192.168.x`, `172.16.x`).
5. **DNS Rebinding Mitigation via IP Pinning**:
   - Once `ScopeGuard::validate_and_resolve()` validates the resolved IP, `HttpClient` pins that exact `host:port:ip` tuple in `libcurl` via `CURLOPT_RESOLVE`. This guarantees `libcurl` connects to the exact IP address that passed validation, completely preventing time-of-check-to-time-of-use (TOCTOU) DNS rebinding.
6. **Manual Redirect Validation**:
   - `CURLOPT_FOLLOWLOCATION` is set to `0L` (disabled).
   - When a `301`, `302`, `303`, `307`, or `308` response is received, `HttpClient` resolves the relative or absolute `Location` header, runs `ScopeGuard::validate_and_resolve()` on the destination URL, and aborts the redirect chain immediately if the destination points to a private IP, localhost, metadata endpoint, excluded path, or out-of-scope domain.

### 3.3 Rate Limiting, Timeouts, Pause/Resume & Emergency Stop
- **Rate Limiter**: Thread-safe token spacer enforcing `max_requests_per_second` (default `5 req/s`, configurable `1–25 req/s`).
- **Timeouts & Retries**: Per-request connection timeout (`5s`), transfer timeout (`10s`), and configurable retry count (`0–2`) on transient network errors.
- **Max Scan Duration**: Hard deadline (`start_time + max_duration_seconds`); engine cleanly terminates remaining checks and marks unexecuted modules as `IncompleteCheck` if exceeded.
- **Pause / Resume / Emergency Stop**:
  - `sentinel_pause_scan(handle)`, `sentinel_resume_scan(handle)`, and `sentinel_cancel_scan(handle)` manipulate atomic flags checked prior to every request and between scanner modules.

---

## 4. Standardized Vulnerability Finding Schema & Redaction

### 4.1 Sensitive Evidence Redaction (`Redactor`)
Before any HTTP body, header, or URL snippet is stored in a `Finding`, it passes through `Redactor::redact()`:
- Masks `Authorization: Bearer ...`, `Basic ...`, API keys (`sk-...`, `AIza...`, `ghp_...`, `xoxb-...`).
- Masks `.env` or config key assignments (`PASSWORD=...`, `SECRET=...`, `TOKEN=...`, `API_KEY=...`, `PRIVATE_KEY=...`, `AWS_SECRET_ACCESS_KEY=...` -> `=[REDACTED]`).
- Masks PEM private key blocks (`-----BEGIN ... PRIVATE KEY-----`).
- Masks `Set-Cookie` session values (`sessionid=abc123xyz` -> `sessionid=[REDACTED]`) while preserving security flags (`; Secure; HttpOnly; SameSite=Lax`) for evidence inspection.

### 4.2 Standardized Finding Fields
Every scanner produces findings adhering to a single unified schema:
- `id`: Deterministic hash (`category|rootCauseKey|affectedURL|affectedParameter`)
- `rootCauseKey`: Grouping identifier for scoring deduplication (e.g., `HEADER_MISSING_CSP`, `SQLI_PARAM_id`)
- `title`: Vulnerability name
- `category`: Module category (`SQL Injection`, `Cross-Site Scripting (XSS)`, `Authentication & Session`, `CSRF`, `Server-Side Security`, `Security Headers`, `TLS / HTTPS`, `API Security`, `Information Disclosure`, `OWASP Top 10`)
- `owaspCategory`: OWASP Top 10 (2021) identifier (`A01:2021` through `A10:2021`)
- `severity`: `Critical` | `High` | `Medium` | `Low` | `Informational`
- `confidence`: `High` | `Medium` | `Low`
- `status`:
  - `Verified` (deterministic proof observed)
  - `Suspected` (behavioral/heuristic indicator)
  - `Informational` (configuration note)
  - `ManualReviewRequired` (requires human verification)
  - `Incomplete` (check could not finish)
- `cvssScore`: `Double` (`0.0` – `10.0`)
- `affectedURL`: String
- `affectedParameter`: String (query parameter, cookie name, header name, or form field)
- `evidence`: Redacted technical evidence snippet
- `technicalExplanation`: Detailed explanation of what was observed and why it was flagged
- `impact`: Concrete security impact if exploited
- `safeReproduction`: Non-destructive step-by-step verification instructions
- `remediation`: Actionable fix instructions + secure code example
- `isResolved`: Boolean (user-togglable in UI & persisted in SQLite)

---

## 5. Comprehensive C++ Vulnerability Scanners (Section 4)

The C++ engine runs 10 modular checks across discovered in-scope pages and endpoints:

### Module 1: TLS / HTTPS Scanner (`run_tls_scanner`)
- Checks if target is served over HTTP vs. HTTPS.
- Tests whether plain `http://` requests enforce a `301`/`308` redirect to `https://`.
- Inspects negotiated TLS version via `CURLINFO_SSL_VERIFYRESULT` and `CURLINFO_TLS_SSL_PTR` / protocol info; flags insecure TLS (`TLSv1.0`, `TLSv1.1`, `SSLv3`) or invalid/self-signed/expired certificates.
- Inspects certificate expiration window via `CURLINFO_CERTINFO`.
- Scans HTTPS HTML documents for mixed content (`http://` `<script src=>`, `<iframe src=>`, `<link rel="stylesheet" href=>`, `<img src=>`, `<form action="http://...">`).

### Module 2: Security Headers Scanner (`run_headers_scanner`)
Evaluates presence, strength, and misconfiguration of:
- `Content-Security-Policy` (flags missing CSP, or weak CSP containing `'unsafe-inline'`, `'unsafe-eval'`, or wildcard `*` in `default-src`/`script-src`).
- `Strict-Transport-Security` (flags missing HSTS on HTTPS or `max-age < 31536000`).
- `X-Content-Type-Options` (flags missing or non-`nosniff` value).
- `X-Frame-Options` & CSP `frame-ancestors` (flags clickjacking exposure).
- `Referrer-Policy` (flags missing or unsafe `unsafe-url` policy).
- `Permissions-Policy` (flags missing browser feature restrictions).
- `Cross-Origin-Resource-Policy` / `Cross-Origin-Opener-Policy`.

### Module 3: Authentication & Session Security Scanner (`run_auth_session_scanner`)
- Inspects all `Set-Cookie` headers across responses:
  - Flags session/auth cookies missing `Secure`, missing `HttpOnly`, missing `SameSite`, or using `SameSite=None` without `Secure`.
  - Checks session expiration (`Max-Age` / `Expires`) for overly long-lived session tokens.
- Analyzes login and password reset pages/forms:
  - Flags login forms submitting over plain HTTP or missing `autocomplete="off"` / proper password attributes.
  - Checks for observable MFA indicators vs. single-factor password forms (`Informational` / `ManualReviewRequired`).
  - Checks for missing rate-limit headers (`Retry-After`, `X-RateLimit-Limit`, `RateLimit-Limit`) on authentication endpoints.

### Module 4: Cross-Site Request Forgery (CSRF) Scanner (`run_csrf_scanner`)
- Parses all HTML `<form>` tags with state-changing methods (`POST`, `PUT`, `DELETE`, `PATCH`).
- Checks whether each form contains an anti-CSRF hidden token input (`csrf`, `_token`, `authenticity_token`, `__RequestVerificationToken`, `xsrf`).
- Correlates missing form tokens with session cookie `SameSite` configuration (`Verified` Medium/High if session cookie lacks `SameSite=Lax/Strict` and form lacks CSRF token; `Suspected` if mitigated only by default Lax cookies).
- Checks sensitive state-changing endpoints for missing `Origin`/`Referer` validation indicators.

### Module 5: Server-Side Security Scanner (`run_server_security_scanner`)
- **Banner & Version Disclosure**: Checks `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` for version numbers (e.g., `Apache/2.2.15`, `PHP/5.4.16`, `Express`).
- **Directory Listing**: Detects open directory indexing (`<title>Index of /`, `Parent Directory</a>`).
- **Unintended Public & Backup Files**: Safely requests high-risk paths (`/.env`, `/.git/HEAD`, `/config.php.bak`, `/backup.zip`, `/web.config.bak`, `/phpinfo.php`, `/server-status`) and compares against a known-404 baseline to eliminate soft-404 false positives.
- **Misconfigured HTTP Methods**: Sends `OPTIONS` request to check `Allow` / `Access-Control-Allow-Methods` for dangerous methods (`TRACE`, `PUT`, `DELETE`).

### Module 6: Information Disclosure Scanner (`run_info_disclosure_scanner`)
- **Exposed Source Maps**: Detects `//# sourceMappingURL=` references and accessible `.js.map` files.
- **Verbose Error Messages & Stack Traces**: Detects framework stack traces (`Traceback (most recent call last):`, `ReferenceError:`, `at Object.<anonymous>`, `java.lang.NullPointerException`, `Fatal error: Uncaught`, `System.NullReferenceException`).
- **Internal IP & Hostname Leaks**: Scans headers and bodies for RFC 1918 private IPs (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`) or internal hostnames (`.internal`, `.corp`, `.local`).
- **Accidental Secret Exposure**: Detects API key/secret patterns in public responses and immediately redacts the values via `Redactor` while flagging the exposure.

### Module 7: API Security Scanner (`run_api_scanner`)
- Discovers API endpoints (`/api/...`, JSON responses, GraphQL `/graphql`) and checks for publicly exposed API documentation (`/swagger.json`, `/openapi.json`, `/api-docs`, `/v1/swagger.json`).
- **CORS Misconfiguration**: Sends a safe request with header `Origin: https://sentinel-cors-audit.example` and checks if `Access-Control-Allow-Origin` echoes the untrusted origin (especially critical when combined with `Access-Control-Allow-Credentials: true`) or uses wildcard `*` on sensitive endpoints.
- **Missing Authentication / Verbose API Responses**: Flags unauthenticated `/api/` endpoints returning user objects or internal schema definitions.

### Module 8: SQL Injection (SQLi) Indicator Scanner (`run_sqli_scanner`)
- **Strictly Non-Destructive**: Never runs `UNION SELECT`, `DROP`, `SLEEP`, or data extraction queries.
- Identifies URL query parameters (e.g., `?id=1`, `?cat=books`).
- Sends a baseline request, followed by safe syntax indicator probes (`'`, `"`, `'/*`) and safe boolean differential probes.
- Checks response for:
  1. **Database Error Signatures (`Verified` High/Critical)**: `SQL syntax`, `mysql_fetch`, `ORA-01756`, `PostgreSQL query failed`, `unterminated quoted string`, `SQLite3::SQLException`, `SQLSTATE[`, `Microsoft OLE DB Provider for SQL Server`.
  2. **Anomalous Boolean/Status Differentials (`Suspected` High)**: When an unescaped quote induces a deterministic `500 Internal Server Error` while an escaped quote `''` restores the `200 OK` baseline response.

### Module 9: Cross-Site Scripting (XSS) Indicator Scanner (`run_xss_scanner`)
- **Reflected XSS Check**: Sends a harmless canary parameter value `sntnl9421<>"'` to discovered query parameters.
  - Inspects whether `<`, `>`, `"`, or `'` are reflected **unencoded** in the HTML response body, attribute values, or `<script>` blocks (`Verified` High when unencoded tag/attribute break characters reflect in `text/html`; `Suspected` Medium if partial reflection occurs).
- **DOM-Based XSS & Unsafe Rendering Check**: Scans inline JavaScript for dangerous source-to-sink patterns (`location.search`, `location.hash`, `document.referrer` flowing into `innerHTML`, `outerHTML`, `document.write()`, `eval()`, `setTimeout(string)`).

### Module 10: Additional OWASP Top 10 Coverage (`run_owasp_scanner`)
- **A01 Broken Access Control**: Checks exposed administrative/debug paths (`/admin`, `/debug`, `/actuator/health`) and missing `Cache-Control: no-store` on authenticated/sensitive pages.
- **A04 Insecure Design**: Flags forms/endpoints lacking anti-automation or rate-limiting indicators.
- **A06 Vulnerable & Outdated Components**: Flags outdated client-side JS libraries (e.g., `jquery-1.`, `jquery-2.`, `angular.js/1.`, `bootstrap/3.`) and outdated server versions.
- **A08 Software & Data Integrity Failures**: Scans external `<script src="https://...">` and `<link rel="stylesheet" href="https://...">` tags for missing Subresource Integrity (`integrity="sha384-..."`) attributes.
- **A09 Security Logging & Monitoring Failures**: Evaluates observable correlation/request-ID headers and error handling posture (`ManualReviewRequired` / `Informational`).
- **A10 SSRF / Open Redirect Indicators**: Identifies query parameters accepting URLs or paths (`?url=`, `?redirect=`, `?next=`, `?dest=`, `?callback=`, `?uri=`) and flags them for SSRF/open-redirect review without attempting internal network exploitation.

---

## 6. Transparent Security Scoring System (Section 6)

Implemented in `Sources/SentinelKit/SecurityScorer.swift`:

1. **Root-Cause Deduplication**:
   - Findings are grouped by `rootCauseKey` (for instance, `HEADER_MISSING_CSP`).
   - If 10 pages are missing `Content-Security-Policy`, the penalty is applied **once** for the root cause, scaled slightly by an exposure factor `min(1.3, 1.0 + 0.05 * Double(affectedURLCount - 1))`.
2. **Weighted Deduction Formula (Starting from 100.0)**:
   - Base weights by severity:
     - `Critical`: `28.0`
     - `High`: `16.0`
     - `Medium`: `7.5`
     - `Low`: `2.5`
     - `Informational`: `0.0`
   - Status multiplier:
     - `Verified`: `1.0`
     - `Suspected`: `0.55`
     - `ManualReviewRequired`: `0.25`
     - `Informational` / `Incomplete`: `0.0`
   - Confidence multiplier:
     - `High`: `1.0`
     - `Medium`: `0.75`
     - `Low`: `0.45`
   - Resolved findings (`isResolved == true`) are excluded from active penalty deductions so users can see their projected/improved score as they remediate issues.
3. **Critical Failure Cap**:
   - If at least one **unresolved, Verified Critical** vulnerability exists, the final score cannot exceed **69 (Grade D)**.
4. **Separate Scan Coverage Percentage**:
   - `coveragePercentage = (Double(completedModules) / Double(totalConfiguredModules)) * 100.0`
   - Untested or cancelled modules are never counted as passing.
5. **Letter Grade Table**:
   - `95–100`: `A+` (Excellent)
   - `90–94`: `A` (Very strong)
   - `85–89`: `B+` (Good)
   - `80–84`: `B` (Above average)
   - `75–79`: `C+` (Moderate)
   - `70–74`: `C` (Needs improvement)
   - `60–69`: `D` (Weak)
   - `0–59`: `F` (Poor)

---

## 7. AI Security Analyst (Section 5 & Section 10)

Implemented in `Sources/SentinelKit/AISecurityAnalyst.swift`:

1. **Built-in Deterministic Security Analyst (Works With Zero API Keys)**:
   - Analyzes the actual scanner `Finding` and the scan's surrounding findings to detect **compound attack chains** (e.g., *Reflected XSS + Missing HttpOnly Cookie = Session Hijacking Chain*; *Missing CSRF Token + Permissive SameSite = Cross-Origin State Modification*; *CORS Origin Reflection + Credentials = Cross-Origin Data Read*).
   - Produces:
     - Plain-English executive summary of the specific finding and captured evidence.
     - Related vulnerabilities in the same scan.
     - Conceptual abuse analysis (non-exploitative).
     - Potential false-positive assessment and how to rule it out.
     - Controlled local validation walkthrough.
     - Framework-specific remediation code patterns (Nginx/Apache, Node/Express, Python/Django/FastAPI, Swift/Vapor, Go).
     - Verification checklist to confirm the fix works.
2. **Optional Cloud AI Enhancement (OpenAI / Anthropic / Google Gemini)**:
   - API keys are stored exclusively in the **macOS Keychain** (`kSecClassGenericPassword`, service `com.sentinel.websitesecuritychecker`).
   - Sends only redacted finding telemetry to the selected provider and renders the AI response in a dedicated **"Enhanced AI Analyst Commentary"** section clearly separated from verified scanner evidence.

---

## 8. Native macOS SwiftUI Interface (Sections 7, 8, 9, 10, 12, 13)

1. **Sidebar Navigation (`MainWindowView`)**:
   - **Dashboard**: Score ring, letter grade badge, coverage gauge, severity counters, Swift Charts historical score trend & severity bar chart, prioritized remediation queue, quick-launch scan button.
   - **New Scan / Live Monitor**: Domain input, authorization confirmation checkbox, scan intensity (`Passive`, `Standard`, `Thorough`), max duration, RPS limit, allowed subdomains, excluded paths, and live scan progress view (current module, endpoints examined, checks completed, live findings counter, estimated remaining work, **Pause/Resume**, **Emergency Stop**).
   - **Findings**: Filter by severity, category, verification status, or unresolved state; search bar; sort by severity/confidence/CVSS; expandable technical evidence, safe reproduction, and remediation panels; mark as resolved button.
   - **Security Investigation**: Deep-dive workbench for any finding with the AI Security Analyst walkthrough, compound risk correlation, controlled validation guide, and fix verification steps.
   - **Scan History & Compare**: Persistent list of all past scans, side-by-side comparison selector showing **Score Change (`+18 pts`)**, **Newly Discovered**, **Resolved**, and **Remaining** vulnerabilities, plus one-click **PDF / HTML / JSON** report export.
   - **Settings & Audit Log**: AI provider configuration (Keychain-backed), setup instructions, local testbench toggle for QA, and persistent authorization audit log table.

---

## 9. Testing Strategy & Local Vulnerable Test Environment (Section 16)

Implemented in `Tests/SentinelTests/`:
1. **`LocalTestServer.swift`**:
   - Uses macOS `Network.framework` (`NWListener`) to spin up a fast, deterministic local HTTP server on `127.0.0.1:<ephemeral_port>` during tests.
   - Serves two route trees:
     - **`/vuln/*` (Deliberately Vulnerable)**:
       - `/vuln/index.html` (missing CSP/HSTS/XFO/XCTO, HTTP mixed content script, external script without SRI, links to sub-endpoints, `Server: Apache/2.2.15`, `Set-Cookie: sessionid=secret123; Path=/`)
       - `/vuln/sqli?id=1` (triggers SQL syntax error when `id` contains `'`)
       - `/vuln/xss?q=test` (reflects `q` unencoded in HTML response)
       - `/vuln/login` (`POST` form with no CSRF token)
       - `/vuln/dir/` (directory listing `Index of /vuln/dir/`)
       - `/vuln/api/data` (reflects `Origin` header with `Access-Control-Allow-Credentials: true` and leaks internal IP `10.24.1.99` + stack trace)
       - `/.env` (exposes `DB_PASSWORD=supersecret` to verify both detection and `[REDACTED]` scrubbing)
     - **`/secure/*` (Hardened Reference)**:
       - Strict `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, `Cross-Origin-Resource-Policy: same-origin`, `Secure; HttpOnly; SameSite=Strict` cookies, anti-CSRF tokens, HTML-encoded output, and parameterized responses.
2. **Automated Test Suite (`SentinelEngineTests.swift`)**:
   - **Authorization & ScopeGuard Tests**: Verifies blocking of unauthorized scans, `127.0.0.1` (when testbench mode is disabled), `10.0.0.1`, `172.16.0.1`, `192.168.1.1`, `169.254.169.254` (cloud metadata), `::1`, out-of-scope domains, and excluded paths.
   - **Redaction Tests**: Verifies passwords, bearer tokens, and cookie values are scrubbed to `[REDACTED]`.
   - **Positive Vulnerability Detection Tests**: Scans `/vuln/*` and verifies detection of SQLi indicator, Reflected XSS, Missing Security Headers, Insecure Cookies, CSRF weakness, Directory Listing, Server Version Disclosure, CORS misconfiguration, `.env` exposure (with redacted secret), and SRI/Mixed Content.
   - **Negative False-Positive Tests**: Scans `/secure/*` and verifies zero false-positive High/Critical/Medium vulnerability flags.
   - **Cancellation & Rate Limit Tests**: Verifies immediate scan cancellation and rate limiting.
   - **Scoring & Deduplication Tests**: Verifies grade boundaries, critical failure cap (`<= 69`), root-cause deduplication, and coverage calculation.
   - **Database & Scan Comparison Tests**: Verifies SQLite save/load, resolved state persistence, audit logging, and scan-to-scan diffing.
   - **Report Export Tests**: Verifies PDF (valid `%PDF-` header and non-empty pages), HTML, and JSON report generation with redacted evidence.

---

## 10. Execution Milestones

1. **Milestone 1**: Initialize repository files (`.gitignore`, `Package.swift`) and implement the C++ `SentinelCore` engine (`scope_guard`, `redactor`, `http_client`, `crawler`, 10 modular scanners, `engine`, `sentinel_bridge`).
2. **Milestone 2**: Implement `SentinelKit` Swift framework (`Models`, `ScannerBridge`, `SecurityScorer`, `DatabaseManager`, `AISecurityAnalyst`, `ReportGenerator`).
3. **Milestone 3**: Implement `WebsiteSecurityChecker` native macOS SwiftUI app (`DashboardView`, `ScanConfigView`, `FindingsView`, `InvestigationView`, `HistoryComparisonView`, `SettingsAuditView`).
4. **Milestone 4**: Implement `LocalTestServer` and comprehensive automated test suite (`SentinelEngineTests`), run `swift test`, and fix any issues until 100% of tests pass.
5. **Milestone 5**: Create `scripts/build-app.sh`, `scripts/uninstall.sh`, `README.md`, and `docs/`, verify the native macOS `.app` bundle builds cleanly, and commit & push all work to `origin/main`.
