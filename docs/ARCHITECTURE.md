# Technical Architecture — Website Security Checker ("Sentinel")

## 1. Hybrid Native macOS Architecture (Swift/SwiftUI + C++17)

Website Security Checker is architected into three strictly separated layers compiled via a single Swift Package (`Package.swift`):

1. **`SentinelCore` (C++17 Security Scanning Engine)**
   - **Location**: `Sources/SentinelCore/`
   - **Responsibilities**:
     - Pre-request URL parsing, path normalization, DNS resolution (`getaddrinfo`), IPv4/IPv6 private/metadata/loopback blocking (`ScopeGuard`).
     - HTTP/HTTPS client (`HttpClient`) wrapping macOS system `libcurl` with `CURLOPT_RESOLVE` IP pinning (defeating DNS rebinding), token-bucket rate limiting, timeouts, and manual `3xx` redirect re-validation.
     - Automatic secret, token, password, and session-cookie redaction (`Redactor`).
     - In-scope HTML link, form, parameter, script, and API endpoint discovery (`Crawler`).
     - 10 independent vulnerability scanner modules (`Scanners`).
     - Scan lifecycle orchestration (`Engine`) supporting live progress streaming, atomic pause/resume, emergency cancellation, and module coverage accounting.
     - Pure C ABI (`sentinel_bridge.h`) for zero-overhead interop with Swift.

2. **`SentinelKit` (Swift Core Framework)**
   - **Location**: `Sources/SentinelKit/`
   - **Responsibilities**:
     - Async/await bridge (`ScannerBridge.swift`) managing C++ engine lifecycle and streaming findings/telemetry to the main actor.
     - Transparent 0–100 security scoring, root-cause deduplication, grade calculation, and scan-to-scan comparison (`SecurityScorer.swift`).
     - Persistent SQLite3 storage (`DatabaseManager.swift`) for scan records, resolved finding flags, and immutable authorization audit logs.
     - Dual-mode AI Security Analyst (`AISecurityAnalyst.swift`) featuring an offline deterministic correlation engine and optional macOS Keychain-backed OpenAI/Anthropic/Gemini LLM analysis.
     - Professional report export (`ReportGenerator.swift`) in native vector PDF (`CoreGraphics`/`CoreText`), standalone HTML, and structured JSON.

3. **`WebsiteSecurityChecker` (Native macOS SwiftUI Application)**
   - **Location**: `Sources/WebsiteSecurityChecker/`
   - **Responsibilities**:
     - Native macOS `NavigationSplitView` desktop experience (`DashboardView`, `ScanConfigView`, `FindingsView`, `InvestigationView`, `HistoryComparisonView`, `SettingsAuditView`).
     - Interactive Swift Charts visualizations, filtering, search, and one-click report exports.

---

## 2. Data Flow During an Assessment

```text
[User Attests Authorization in SwiftUI]
        │
        ▼
[DatabaseManager] ──► Writes immutable entry to SQLite `audit_logs`
        │
        ▼
[ScannerBridge (Swift)] ──► Serializes ScanConfiguration to C++ Engine
        │
        ▼
[ScopeGuard (C++)] ──► Validates scheme, domain, allowed subdomains, excluded paths,
        │              resolves DNS, blocks private/loopback/metadata IPs, pins IP
        ▼
[Crawler (C++)] ──► Discovers in-scope pages, forms, query parameters, scripts, APIs
        │
        ▼
[10 Modular C++ Scanners] ──► Emits Redacted Findings & Progress via C Callbacks
        │
        ▼
[SecurityScorer & AISecurityAnalyst (Swift)] ──► Deduplicates root causes, calculates
        │                                        0–100 score + coverage %, enriches AI analysis
        ▼
[SQLite Persistence & SwiftUI Views]
```
