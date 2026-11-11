# Website Security Checker (Sentinel)
### AI-Powered Native macOS Website Security Auditing Platform

Website Security Checker (**Sentinel**) is a native macOS cybersecurity auditing platform built with **Swift & SwiftUI** for the desktop experience and a modular **C++17** security scanning engine (`SentinelCore`). It performs authorized, non-destructive vulnerability assessments, collects redacted technical evidence, calculates transparent 0–100 security scores, provides AI-assisted vulnerability investigations, tracks historical remediation progress, and exports professional PDF, HTML, and JSON reports.

---

## 1. Feature Implementation Status

| Feature Category | Status | Details |
|---|---|---|
| **Native macOS Application (Swift + SwiftUI)** | **Fully Implemented** | Dark-first macOS `NavigationSplitView` interface with Dashboard, Scan Config & Live Monitor, Findings Explorer, AI Investigation Workbench, Scan History & Diff Comparison, and Settings & Audit Logs. |
| **Authorization & Scope Guard (C++)** | **Fully Implemented** | Mandatory authorization confirmation, persistent SQLite audit logs, domain/subdomain scope enforcement, excluded path normalization, DNS resolution validation, IP pinning (`CURLOPT_RESOLVE`) against DNS rebinding, manual redirect validation, and blocking of private/loopback/cloud-metadata IPs. |
| **10 Modular C++ Vulnerability Scanners** | **Fully Implemented** | Covers SQL Injection indicators, Reflected & DOM XSS indicators, Authentication & Session Cookies, CSRF protections, Server-Side Misconfigurations (`.env`, `.git/HEAD`, directory listing, version banners, HTTP methods), Security Headers (CSP, HSTS, XFO, XCTO, Referrer, Permissions, CORP), TLS/HTTPS & Mixed Content, API Security (CORS reflection), Information Disclosure (stack traces, internal IPs, source maps), and OWASP Top 10 (SRI, outdated JS libraries, SSRF/Redirect parameters). |
| **Sensitive Evidence Redaction** | **Fully Implemented** | Automatically scrubs passwords, bearer tokens, API keys, PEM keys, and session cookie values to `[REDACTED]` before storage or display. |
| **Security Scoring & Coverage System** | **Fully Implemented** | Transparent 0–100 algorithm with `A+` to `F` letter grades, root-cause deduplication, Critical Failure Cap (`<= 69`), and independent Scan Coverage % tracking. |
| **AI Security Analyst (Offline + Cloud LLM)** | **Fully Implemented** | Works out-of-the-box without an API key using the built-in **Deterministic Security Analyst** (with compound risk correlation and secure code patterns). Optional cloud LLM enhancement (OpenAI, Anthropic, Google Gemini) when API keys are saved in **macOS Keychain**. |
| **Report Export (PDF, HTML, JSON)** | **Fully Implemented** | Native macOS vector PDF generator (`CoreGraphics`/`CoreText`), standalone styled HTML reports, and machine-readable JSON exports. |
| **Local Vulnerable & Secure Testbench** | **Fully Implemented** | Embedded `LocalTestServer` + `SentinelTestRunner` verifying positive detection across all 10 modules and zero false positives on hardened routes. |

---

## 2. Technology Stack & Architecture

- **Frontend & App Layer**: Swift 5.9+ / 6, SwiftUI, Swift Charts, AppKit (`WebsiteSecurityChecker`)
- **Core Domain, Scoring, Persistence & Reports**: Swift (`SentinelKit`), SQLite3 (`-lsqlite3`), macOS Keychain (`Security.framework`), `PDFKit` / `CoreGraphics`
- **Security Scanning Engine**: C++17 (`SentinelCore`), macOS system `libcurl` (`-lcurl`), POSIX `getaddrinfo` / `inet_pton`
- **Swift <-> C++ Bridge**: Pure C ABI (`Sources/SentinelCore/include/sentinel_bridge.h`) with live progress and finding callbacks

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/SCORING.md](docs/SCORING.md), and [docs/SECURITY_CONSIDERATIONS.md](docs/SECURITY_CONSIDERATIONS.md) for detailed technical documentation.

---

## 3. Prerequisites & Dependencies

- **Operating System**: macOS 14.0 (Sonoma) or newer
- **Toolchain**: Xcode or Apple Command Line Tools (`xcode-select --install`)
- **External Third-Party Libraries**: **None required.** All libraries (`libcurl`, `libsqlite3`, `Security.framework`, `SwiftUI`, `Charts`, `PDFKit`) are included in the standard macOS SDK.

---

## 4. Building, Running & Installing on macOS

### Option A: Run Directly from Source via SwiftPM
```bash
git clone git@github.com:raymondtian30/Website-security-checker.git
cd Website-security-checker
swift run WebsiteSecurityChecker
```

### Option B: Build & Install the Native macOS `.app` Bundle
```bash
chmod +x scripts/build-app.sh
./scripts/build-app.sh

# Launch the packaged macOS app:
open dist/WebsiteSecurityChecker.app

# Or copy to /Applications:
cp -R dist/WebsiteSecurityChecker.app /Applications/
```

---

## 5. Uninstallation Instructions

To cleanly remove the application bundle, local SQLite scan history database (`~/Library/Application Support/WebsiteSecurityChecker`), and any AI API keys stored in the macOS Keychain:

```bash
chmod +x scripts/uninstall.sh
./scripts/uninstall.sh
```

---

## 6. AI API Key Setup (Optional)

Website Security Checker **does not require an API key** to function. Every finding is automatically analyzed by the built-in **Deterministic Security Analyst**.

To enable enhanced cloud LLM commentary:
1. Open **Website Security Checker** and navigate to **Settings & Audit Log** in the left sidebar.
2. Select your preferred provider (**OpenAI**, **Anthropic**, or **Google Gemini**).
3. Paste your API key and click **Save to Keychain**.
   - Keys are stored strictly in the encrypted **macOS Keychain** (`com.sentinel.WebsiteSecurityChecker.AIKeys`) and are never hardcoded or written to plaintext files.
   - Only redacted scanner evidence is transmitted when you click **Run Enhanced Cloud AI Analysis** in the **AI Investigation** tab.

---

## 7. Running Scans & Generating Reports

1. Navigate to **Scan & Monitor** in the sidebar.
2. Enter your authorized target URL (e.g., `https://example.com`).
3. Check the mandatory **Authorization Confirmation** box.
4. Configure **Allowed Subdomains**, **Excluded Paths** (defaults: `/logout, /signout, /delete`), **Scan Intensity** (`Passive`, `Standard`, `Thorough`), **Rate Limit** (`req/sec`), and **Max Duration**.
5. Click **Start Authorized Security Scan**.
   - Monitor live telemetry, pause/resume at any time, or click **EMERGENCY STOP** to halt all requests immediately.
6. Inspect results in **Dashboard**, **Findings**, and **AI Investigation**.
7. Export reports in **PDF**, **HTML**, or **JSON** from the **Dashboard** or **History & Compare** view.

---

## 8. Running Automated Tests & Local Vulnerable Testbench

The repository includes an automated test suite (`SentinelTestRunner`) that spins up an ephemeral local HTTP server (`LocalTestServer`) on `127.0.0.1` hosting both **deliberately vulnerable** endpoints (`/vuln/*`, `/.env`, `/.git/HEAD`) and **hardened secure** endpoints (`/secure/*`).

Run the entire automated verification suite with:

```bash
swift run SentinelTestRunner
```

What is tested:
1. **Authorization & Scope Guard**: Verifies blocking of unauthorized scans, loopback in production mode, RFC 1918 private IPs (`10.0.0.1`, `172.16.5.4`, `192.168.1.1`), cloud metadata (`169.254.169.254`), out-of-scope domains, and excluded paths (including `/../` path traversal).
2. **Sensitive Data Redaction**: Verifies passwords, bearer tokens, API keys, and cookie values are scrubbed to `[REDACTED]`.
3. **Positive Vulnerability Detection**: Verifies all 10 C++ scanner modules accurately detect SQLi indicators, Reflected & DOM XSS, Missing Security Headers, Insecure Cookies, CSRF weaknesses, Directory Listing, `.env` & `.git` exposure, Stack Traces, Internal IP leaks, CORS misconfiguration, Missing SRI, and Outdated JS libraries.
4. **Negative False-Positive Verification**: Verifies hardened routes (`/secure/*`) produce zero Critical/High/Medium false positives and achieve an `A+` score.
5. **Emergency Cancellation & Coverage**: Verifies mid-scan cancellation stops execution and marks unexecuted modules as `Incomplete`.
6. **Scoring & Deduplication**: Verifies root-cause deduplication, Critical Failure Cap (`<= 69`), and grade boundaries.
7. **SQLite Persistence & Reports**: Verifies scan saving, resolved state toggling, scan comparison diffing, audit logging, and PDF/HTML/JSON report generation.

---

## 9. Troubleshooting & Known Limitations

- **Scan Blocked by Scope Guard**: Ensure the target URL uses `http://` or `https://`, matches the configured Target Domain or Allowed Subdomains, and resolves to a public IP address. If testing a local development server on `127.0.0.1` (port `>= 1024`), enable **Local Testbench Mode** in Scan Configuration.
- **Scanner Limitations**: Sentinel performs non-destructive HTTP/HTML/header/parameter indicator analysis. It does not execute headless browser JavaScript rendering for complex client-only SPAs, nor does it perform credential attacks or state-changing exploitation.
