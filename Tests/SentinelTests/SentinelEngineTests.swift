import Foundation
import SentinelKit

struct TestFailure: Error, CustomStringConvertible {
    let message: String
    let file: String
    let line: Int
    var description: String { "\(file):\(line) — \(message)" }
}

func assertTrue(_ condition: @autoclosure () -> Bool, _ message: String = "Assertion failed", file: String = #fileID, line: Int = #line) throws {
    if !condition() {
        throw TestFailure(message: message, file: file, line: line)
    }
}

func assertFalse(_ condition: @autoclosure () -> Bool, _ message: String = "Expected false", file: String = #fileID, line: Int = #line) throws {
    if condition() {
        throw TestFailure(message: message, file: file, line: line)
    }
}

func assertEqual<T: Equatable>(_ a: T, _ b: T, _ message: String = "", file: String = #fileID, line: Int = #line) throws {
    if a != b {
        throw TestFailure(message: "Expected \(a) == \(b). \(message)", file: file, line: line)
    }
}

@main
struct SentinelTestMain {
    static func main() async {
        print("======================================================================")
        print("SENTINEL AUTOMATED QA & VULNERABILITY BENCHMARK SUITE")
        print("======================================================================")

        var passed = 0
        var failed = 0

        func runTest(_ name: String, _ block: () async throws -> Void) async {
            print("▶ Running: \(name) ...", terminator: " ")
            fflush(stdout)
            do {
                try await block()
                passed += 1
                print("✅ PASSED")
            } catch {
                failed += 1
                print("❌ FAILED\n   Reason: \(error)")
            }
        }

        guard let server = try? LocalTestServer() else {
            print("❌ FATAL: Failed to start LocalTestServer")
            Foundation.exit(1)
        }
        defer { server.stop() }
        print("Local Vulnerable & Hardened Test Server listening on 127.0.0.1:\(server.port)\n")

        // Test 1: Authorization & Scope Guard Enforcement
        await runTest("1. Authorization, SSRF, Private IP, Metadata & Path Scope Enforcement") {
            let unauthConfig = ScanConfiguration(
                targetURL: "https://example.com",
                targetDomain: "example.com",
                authorized: false
            )
            let unauthRes = ScannerBridge.validateScope(config: unauthConfig, candidateURL: "https://example.com")
            try assertFalse(unauthRes.allowed, "Scan must be blocked when authorized is false")
            try assertTrue(unauthRes.reason.lowercased().contains("authorization"), "Reason should mention authorization")

            let prodConfig = ScanConfiguration(
                targetURL: "http://127.0.0.1:8080",
                targetDomain: "127.0.0.1",
                authorized: true,
                allowLocalTestbench: false
            )
            let loopbackBlocked = ScannerBridge.validateScope(config: prodConfig, candidateURL: "http://127.0.0.1:8080/index.html")
            try assertFalse(loopbackBlocked.allowed, "Loopback must be blocked when allowLocalTestbench is false")

            for forbiddenIP in ["10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254", "100.100.100.200", "0.0.0.0", "[::1]", "[fe80::1]"] {
                let internalConfig = ScanConfiguration(
                    targetURL: "http://\(forbiddenIP):8080",
                    targetDomain: forbiddenIP.replacingOccurrences(of: "[", with: "").replacingOccurrences(of: "]", with: ""),
                    authorized: true,
                    allowLocalTestbench: (forbiddenIP != "[::1]")
                )
                let check = ScannerBridge.validateScope(config: internalConfig, candidateURL: "http://\(forbiddenIP):8080/")
                try assertFalse(check.allowed, "Forbidden IP \(forbiddenIP) must always be blocked by ScopeGuard")
            }

            let scopedConfig = ScanConfiguration(
                targetURL: "http://127.0.0.1:\(server.port)/vuln/index.html",
                targetDomain: "127.0.0.1",
                authorized: true,
                excludedPaths: ["/logout", "/admin/delete"],
                allowLocalTestbench: true
            )
            let thirdPartyCheck = ScannerBridge.validateScope(config: scopedConfig, candidateURL: "https://evil-thirdparty.org/api")
            try assertFalse(thirdPartyCheck.allowed, "Out-of-scope domain must be rejected")

            let excludedCheck = ScannerBridge.validateScope(config: scopedConfig, candidateURL: "http://127.0.0.1:\(server.port)/logout")
            try assertFalse(excludedCheck.allowed, "Excluded path /logout must be blocked")

            let traversalCheck = ScannerBridge.validateScope(config: scopedConfig, candidateURL: "http://127.0.0.1:\(server.port)/public/../logout")
            try assertFalse(traversalCheck.allowed, "Normalized path traversal to /logout must be blocked")

            let validCheck = ScannerBridge.validateScope(config: scopedConfig, candidateURL: "http://127.0.0.1:\(server.port)/vuln/index.html")
            try assertTrue(validCheck.allowed, "Authorized local testbench target should be allowed: \(validCheck.reason)")
        }

        // Test 2: Sensitive Evidence Redaction
        await runTest("2. Automatic Sensitive Data Redaction (Passwords, Tokens, API Keys, Cookies)") {
            let raw = """
            Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret
            DB_PASSWORD=super_secret_password_999
            OPENAI_API_KEY=sk-proj1234567890abcdefghij
            Set-Cookie: sessionid=my_live_session_token_abc123; Secure; HttpOnly
            """
            let redacted = ScannerBridge.redact(raw)
            try assertFalse(redacted.contains("super_secret_password_999"), "Password was not redacted")
            try assertFalse(redacted.contains("sk-proj1234567890abcdefghij"), "API key was not redacted")
            try assertFalse(redacted.contains("my_live_session_token_abc123"), "Session token was not redacted")
            try assertTrue(redacted.contains("[REDACTED]"), "Expected [REDACTED] marker")
        }

        // Test 3: Positive Vulnerability Detection Against Local Vulnerable Server
        await runTest("3. Positive Detection Across All 10 Scanner Modules on Vulnerable App") {
            let config = ScanConfiguration(
                targetURL: "http://127.0.0.1:\(server.port)/vuln/index.html",
                targetDomain: "127.0.0.1",
                authorized: true,
                intensity: ScanIntensity.thorough.rawValue,
                maxDurationSeconds: 60,
                maxRequestsPerSecond: 25,
                allowLocalTestbench: true
            )

            let bridge = ScannerBridge()
            let record = try await bridge.executeScan(
                config: config,
                onProgress: { _ in },
                onFinding: { _ in }
            )

            try assertEqual(record.status, "Completed")
            try assertEqual(record.scoreBreakdown.coveragePercent, 100.0)
            try assertTrue(record.endpointsExamined >= 5, "Expected at least 5 endpoints examined")

            let rootCauses = Set(record.findings.map(\.rootCauseKey))
            let expectedCauses = [
                "SQLI_ERROR_BASED_id",
                "XSS_REFLECTED_q",
                "XSS_DOM_SINK",
                "HEADER_MISSING_CSP",
                "HEADER_MISSING_HSTS",
                "HEADER_MISSING_XFO",
                "HEADER_MISSING_XCTO",
                "COOKIE_MISSING_HTTPONLY_sessionid",
                "COOKIE_MISSING_SECURE_sessionid",
                "COOKIE_MISSING_SAMESITE_sessionid",
                "CSRF_MISSING_TOKEN",
                "SERVER_DIRECTORY_LISTING",
                "SERVER_EXPOSED_ENV_FILE",
                "SERVER_EXPOSED_GIT_REPO",
                "INFO_STACK_TRACE",
                "INFO_INTERNAL_IP",
                "API_CORS_ARBITRARY_ORIGIN_CREDS",
                "OWASP_MISSING_SRI",
                "OWASP_OUTDATED_JS_LIB",
                "MALWARE_CRYPTOJACKER",
                "MALWARE_OBFUSCATED_DROPPER",
                "MALWARE_WEB_SKIMMER",
                "MALWARE_HIDDEN_IFRAME",
                "COOKIE_THEFT_TOKEN_IN_URL",
                "COOKIE_THEFT_WEB_STORAGE_TOKEN",
                "INJECTION_NICHE_ENGINE_ERROR",
                "INJECTION_PROTOTYPE_POLLUTION",
                "INJECTION_LFI_PATH_PARAM_file",
                "PLUGIN_EXPOSURE_vulnerable-slider",
                "DDOS_RESILIENCE_MISSING_EDGE_THROTTLING",
                "DDOS_PLUGIN_XMLRPC_ENABLED"
            ]

            for expected in expectedCauses {
                try assertTrue(rootCauses.contains(expected), "Missing expected finding root cause: \(expected). Found: \(rootCauses)")
            }

            let visitorSafety = SecurityScorer.evaluateVisitorSafety(
                findings: record.findings,
                overallScore: record.scoreBreakdown.overallScore
            )
            try assertFalse(visitorSafety.isSafeToVisit, "Infected target must be marked Unsafe to Visit")
            try assertEqual(visitorSafety.safetyGrade, "F")
            try assertTrue(visitorSafety.detectedMalware.count >= 4, "Expected at least 4 malware threats detected")

            if let envFinding = record.findings.first(where: { $0.rootCauseKey == "SERVER_EXPOSED_ENV_FILE" }) {
                try assertFalse(envFinding.evidence.contains("super_secret_database_password_987"), "Raw password leaked in .env evidence")
                try assertTrue(envFinding.evidence.contains("[REDACTED]"), "Expected redacted secret in .env evidence")
                try assertTrue(envFinding.evidence.contains("[Deep Non-Destructive Verification Report]"), "Expected Stage 2 Deep Non-Destructive Verification trail in finding evidence")
            }

            try assertTrue(record.scoreBreakdown.overallScore <= 69, "Verified critical vulnerabilities must cap score at <= 69")
        }

        // Test 4: Negative Test Against Hardened Secure Routes
        await runTest("4. Negative Test — Zero False Positives on Hardened Secure Routes") {
            let config = ScanConfiguration(
                targetURL: "http://127.0.0.1:\(server.port)/secure/index.html",
                targetDomain: "127.0.0.1",
                authorized: true,
                intensity: ScanIntensity.thorough.rawValue,
                maxDurationSeconds: 60,
                maxRequestsPerSecond: 25,
                allowLocalTestbench: true
            )

            let bridge = ScannerBridge()
            let record = try await bridge.executeScan(
                config: config,
                onProgress: { _ in },
                onFinding: { _ in }
            )

            let falsePositives = record.findings.filter {
                $0.severity == .critical || $0.severity == .high || $0.severity == .medium
            }
            try assertTrue(
                falsePositives.isEmpty,
                "Expected zero Critical/High/Medium findings on hardened routes, got: \(falsePositives.map(\.title))"
            )
            try assertTrue(record.scoreBreakdown.overallScore >= 95, "Expected A+ score (>=95) on hardened routes, got \(record.scoreBreakdown.overallScore)")
            try assertEqual(record.scoreBreakdown.letterGrade, "A+")

            let cleanSafety = SecurityScorer.evaluateVisitorSafety(
                findings: record.findings,
                overallScore: record.scoreBreakdown.overallScore
            )
            try assertTrue(cleanSafety.isSafeToVisit, "Clean hardened target must be marked Safe to Visit")
            try assertEqual(cleanSafety.safetyScore, 100)
            try assertEqual(cleanSafety.safetyGrade, "A+")
            try assertTrue(cleanSafety.detectedMalware.isEmpty, "Clean target must have 0 malware threats")
        }

        // Test 5: Scan Cancellation & Incomplete Coverage Handling
        await runTest("5. Emergency Scan Cancellation & Incomplete Check Coverage Accounting") {
            let config = ScanConfiguration(
                targetURL: "http://127.0.0.1:\(server.port)/vuln/index.html",
                targetDomain: "127.0.0.1",
                authorized: true,
                intensity: ScanIntensity.thorough.rawValue,
                maxDurationSeconds: 60,
                maxRequestsPerSecond: 2, // slow rate so cancellation intercepts mid-scan
                allowLocalTestbench: true
            )

            let bridge = ScannerBridge()
            Task {
                try? await Task.sleep(nanoseconds: 250_000_000) // 250ms
                bridge.cancel()
            }

            let record = try await bridge.executeScan(
                config: config,
                onProgress: { _ in },
                onFinding: { _ in }
            )

            try assertEqual(record.status, "Cancelled")
            try assertTrue(record.scoreBreakdown.coveragePercent < 100.0, "Cancelled scan must report < 100% coverage")
            let hasIncompleteNotice = record.findings.contains { $0.status == .incomplete }
            try assertTrue(hasIncompleteNotice, "Cancelled scan must mark unexecuted modules as Incomplete rather than passing")
        }

        // Test 6: Security Scoring Deduplication & Grade Thresholds
        await runTest("6. Security Scoring Algorithm, Deduplication & Grade Thresholds") {
            let repeatedFindings = (1...6).map { idx in
                VulnerabilityFinding(
                    id: "F-\(idx)",
                    rootCauseKey: "HEADER_MISSING_CSP",
                    title: "Missing CSP",
                    category: "Security Headers",
                    owaspCategory: "A05:2021",
                    severity: .medium,
                    confidence: .high,
                    status: .verified,
                    cvssScore: 5.3,
                    affectedURL: "https://example.com/page\(idx)",
                    affectedParameter: "Content-Security-Policy",
                    evidence: "Missing CSP",
                    technicalExplanation: "Missing CSP",
                    impact: "XSS impact",
                    safeReproduction: "curl -I",
                    remediation: "Add CSP"
                )
            }

            let breakdown = SecurityScorer.calculateScore(findings: repeatedFindings, completedChecks: 10, totalChecks: 10)
            try assertEqual(breakdown.deduplicatedRootCauses, 1)
            try assertTrue(breakdown.overallScore >= 90, "Deduplicated single medium root cause should keep score >= 90")

            try assertEqual(SecurityScorer.gradeAndMeaning(for: 97, coveragePercent: 100).0, "A+")
            try assertEqual(SecurityScorer.gradeAndMeaning(for: 92, coveragePercent: 100).0, "A")
            try assertEqual(SecurityScorer.gradeAndMeaning(for: 87, coveragePercent: 100).0, "B+")
            try assertEqual(SecurityScorer.gradeAndMeaning(for: 82, coveragePercent: 100).0, "B")
            try assertEqual(SecurityScorer.gradeAndMeaning(for: 77, coveragePercent: 100).0, "C+")
            try assertEqual(SecurityScorer.gradeAndMeaning(for: 72, coveragePercent: 100).0, "C")
            try assertEqual(SecurityScorer.gradeAndMeaning(for: 65, coveragePercent: 100).0, "D")
            try assertEqual(SecurityScorer.gradeAndMeaning(for: 40, coveragePercent: 100).0, "F")
        }

        // Test 7: SQLite Persistence, Scan Comparison, AI Analyst & PDF/HTML/JSON Reports
        await runTest("7. SQLite Persistence, Remediation Tracking, AI Analyst & PDF/HTML/JSON Reports") {
            let tempDBPath = FileManager.default.temporaryDirectory
                .appendingPathComponent("sentinel_test_\(UUID().uuidString).sqlite3").path
            defer { try? FileManager.default.removeItem(atPath: tempDBPath) }

            let db = DatabaseManager(customPath: tempDBPath)

            let f1 = VulnerabilityFinding(
                id: "FND-1",
                rootCauseKey: "SQLI_ERROR_BASED_id",
                title: "SQL Injection Indicator",
                category: "SQL Injection",
                owaspCategory: "A03:2021-Injection",
                severity: .critical,
                confidence: .high,
                status: .verified,
                cvssScore: 9.8,
                affectedURL: "https://example.com/item?id=1",
                affectedParameter: "id",
                evidence: "MySQL syntax error",
                technicalExplanation: "Unescaped quote",
                impact: "Database compromise",
                safeReproduction: "Send quote",
                remediation: "Use prepared statements"
            )
            let f2 = VulnerabilityFinding(
                id: "FND-2",
                rootCauseKey: "HEADER_MISSING_CSP",
                title: "Missing Content-Security-Policy",
                category: "Security Headers",
                owaspCategory: "A05:2021-Security Misconfiguration",
                severity: .medium,
                confidence: .high,
                status: .verified,
                cvssScore: 5.3,
                affectedURL: "https://example.com/",
                affectedParameter: "Content-Security-Policy",
                evidence: "No CSP header",
                technicalExplanation: "Missing CSP",
                impact: "XSS risk",
                safeReproduction: "curl -I",
                remediation: "Add CSP"
            )

            let aiResult = AISecurityAnalyst.generateDeterministicAnalysis(for: f1, allFindings: [f1, f2])
            try assertFalse(aiResult.plainLanguageSummary.isEmpty)
            try assertFalse(aiResult.secureCodePattern.isEmpty)

            let cfg = ScanConfiguration(targetURL: "https://example.com", targetDomain: "example.com", authorized: true)
            let sb1 = SecurityScorer.calculateScore(findings: [f1, f2], completedChecks: 10, totalChecks: 10)
            let scan1 = ScanRecord(
                timestamp: Date().addingTimeInterval(-3600),
                targetURL: "https://example.com",
                targetDomain: "example.com",
                configuration: cfg,
                scoreBreakdown: sb1,
                findings: [f1, f2],
                status: "Completed",
                endpointsExamined: 5,
                durationSeconds: 4
            )
            try db.saveScan(scan1)

            let toggled = try db.toggleFindingResolved(scanID: scan1.id, findingID: "FND-1")
            try assertTrue(toggled != nil)
            try assertTrue(toggled!.scoreBreakdown.overallScore > sb1.overallScore, "Resolving critical finding must improve score")

            let sb2 = SecurityScorer.calculateScore(findings: [f2], completedChecks: 10, totalChecks: 10)
            let scan2 = ScanRecord(
                timestamp: Date(),
                targetURL: "https://example.com",
                targetDomain: "example.com",
                configuration: cfg,
                scoreBreakdown: sb2,
                findings: [f2],
                status: "Completed",
                endpointsExamined: 5,
                durationSeconds: 3
            )
            try db.saveScan(scan2)

            let diff = SecurityScorer.compareScans(baseline: scan1, current: scan2)
            try assertEqual(diff.resolvedFindings.count, 1)
            try assertTrue(diff.scoreDelta > 0)

            let jsonData = try ReportGenerator.generateJSONReport(for: scan1)
            try assertTrue(jsonData.count > 100)

            let htmlStr = ReportGenerator.generateHTMLReport(for: scan1)
            try assertTrue(htmlStr.contains("Website Security Audit Report"))

            let pdfData = ReportGenerator.generatePDFReport(for: scan1)
            try assertTrue(pdfData.count > 500)
            let pdfHeader = String(decoding: pdfData.prefix(5), as: UTF8.self)
            try assertEqual(pdfHeader, "%PDF-")
        }

        print("======================================================================")
        print("TEST SUMMARY: \(passed) Passed, \(failed) Failed")
        print("======================================================================")
        if failed > 0 {
            Foundation.exit(1)
        }
    }
}
