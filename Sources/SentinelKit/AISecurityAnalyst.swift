import Foundation
import Security

public enum AIProvider: String, CaseIterable, Codable, Sendable {
    case openAI = "OpenAI"
    case anthropic = "Anthropic"
    case gemini = "Google Gemini"

    public var defaultModel: String {
        switch self {
        case .openAI: return "gpt-4o-mini"
        case .anthropic: return "claude-3-5-haiku-latest"
        case .gemini: return "gemini-2.0-flash"
        }
    }

    public var setupInstructions: String {
        switch self {
        case .openAI:
            return "Create an API key at platform.openai.com/api-keys and paste it below. Stored securely in macOS Keychain."
        case .anthropic:
            return "Create an API key at console.anthropic.com/settings/keys and paste it below. Stored securely in macOS Keychain."
        case .gemini:
            return "Create an API key at aistudio.google.com/app/apikey and paste it below. Stored securely in macOS Keychain."
        }
    }
}

public struct KeychainHelper {
    private static let service = "com.sentinel.WebsiteSecurityChecker.AIKeys"

    public static func saveKey(_ key: String, for provider: AIProvider) -> Bool {
        let account = provider.rawValue
        deleteKey(for: provider)
        guard let data = key.data(using: .utf8) else { return false }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    public static func loadKey(for provider: AIProvider) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: provider.rawValue,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    @discardableResult
    public static func deleteKey(for provider: AIProvider) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: provider.rawValue
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}

public struct AISecurityAnalyst {
    public static func generateDeterministicAnalysis(
        for finding: VulnerabilityFinding,
        allFindings: [VulnerabilityFinding]
    ) -> AIAnalysisResult {
        // 1. Identify correlated findings across the scan
        var correlations: [String] = []
        let hasXSS = allFindings.contains { $0.category.contains("XSS") }
        let hasMissingHttpOnly = allFindings.contains { $0.rootCauseKey.contains("COOKIE_MISSING_HTTPONLY") }
        let hasMissingCSP = allFindings.contains { $0.rootCauseKey == "HEADER_MISSING_CSP" }
        let hasCSRF = allFindings.contains { $0.category == "CSRF" }
        let hasMissingSameSite = allFindings.contains { $0.rootCauseKey.contains("COOKIE_MISSING_SAMESITE") }
        let hasStackTrace = allFindings.contains { $0.rootCauseKey == "INFO_STACK_TRACE" }

        if finding.category.contains("XSS") || finding.rootCauseKey.contains("COOKIE_MISSING_HTTPONLY") {
            if hasXSS && hasMissingHttpOnly {
                correlations.append("Compound Risk (XSS + Missing HttpOnly Cookie): Because session cookies lack HttpOnly and an XSS indicator is present, injected script could read `document.cookie` to hijack active user sessions.")
            }
            if hasXSS && hasMissingCSP {
                correlations.append("Compound Risk (XSS + Missing CSP): The absence of a Content-Security-Policy allows reflected scripts to execute and exfiltrate data to external origins unhindered.")
            }
        }

        if finding.category == "CSRF" && hasMissingSameSite && hasCSRF {
            correlations.append("Compound Risk (Missing CSRF Token + Missing SameSite Cookie): State-changing forms lack anti-CSRF tokens while cookies omit explicit SameSite protection, increasing cross-origin forgery exposure.")
        }

        if finding.category == "SQL Injection" && hasStackTrace {
            correlations.append("Compound Risk (SQLi Indicator + Verbose Error Disclosure): Detailed backend errors accelerate query structure inference.")
        }

        if correlations.isEmpty {
            let sameCategoryCount = allFindings.filter { $0.category == finding.category && $0.id != finding.id }.count
            if sameCategoryCount > 0 {
                correlations.append("\(sameCategoryCount) other finding(s) in the '\(finding.category)' category were also identified during this scan and should be remediated together.")
            } else {
                correlations.append("No direct multi-step chaining vulnerabilities were observed alongside this finding in the current scan scope.")
            }
        }

        // 2. Plain-language explanation grounded in actual scanner evidence
        let summary = """
        Sentinel flagged "\(finding.title)" on `\(finding.affectedURL)` (component: `\(finding.affectedParameter)`) with \(finding.status.displayLabel) status and \(finding.confidence.rawValue) confidence. \
        \(finding.technicalExplanation)
        """

        // 3. Conceptual abuse & false-positive analysis
        let conceptualAbuse: String
        let codePattern: String
        switch finding.category {
        case "SQL Injection":
            conceptualAbuse = "When untrusted parameter input alters SQL syntax structure, an adversary can modify boolean predicates or append queries if input is concatenated directly into SQL strings."
            codePattern = """
            // Secure Pattern: Parameterized Query (Prepared Statement)
            // Python (psycopg2 / sqlite3)
            cursor.execute("SELECT id, name FROM items WHERE id = %s", (user_id,))

            // Node.js (pg)
            await pool.query("SELECT id, name FROM items WHERE id = $1", [userId]);
            """
        case "Cross-Site Scripting (XSS)":
            conceptualAbuse = "When special characters (`<`, `>`, `\"`, `'`) are reflected unencoded into HTML or passed into `innerHTML`, browser parsers treat data as executable script within the victim's origin."
            codePattern = """
            // Secure Pattern: Context-Sensitive Output Encoding & Safe DOM APIs
            // Browser DOM (Safe text insertion)
            element.textContent = untrustedSearchQuery; // Never use innerHTML for user input

            // Server-side HTML Escaping
            function escapeHTML(str) {
              return str.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',\"'\":'&#39;'}[c]));
            }
            """
        case "CSRF":
            conceptualAbuse = "Without an unpredictable anti-CSRF token or strict SameSite cookie policy, a third-party page can trigger a background cross-origin form submission using the user's ambient session cookies."
            codePattern = """
            <!-- Secure Pattern: Synchronizer CSRF Token + SameSite Cookie -->
            <form method="POST" action="/account/update">
              <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
              <!-- form fields -->
            </form>
            Set-Cookie: session_id=...; Secure; HttpOnly; SameSite=Lax
            """
        case "Security Headers":
            conceptualAbuse = "Missing browser defense-in-depth headers leave the client without explicit framing, MIME-sniffing, or script-execution boundaries."
            codePattern = """
            # Nginx Secure Headers Configuration
            add_header Content-Security-Policy "default-src 'self'; script-src 'self'; frame-ancestors 'none'; object-src 'none';" always;
            add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
            add_header X-Content-Type-Options "nosniff" always;
            add_header X-Frame-Options "DENY" always;
            add_header Referrer-Policy "strict-origin-when-cross-origin" always;
            """
        case "Authentication & Session":
            conceptualAbuse = "Cookies lacking `Secure`, `HttpOnly`, or `SameSite` flags can be exposed over unencrypted links, read by injected JavaScript, or sent with cross-site requests."
            codePattern = """
            // Express / Node.js Secure Session Cookie Configuration
            app.use(session({
              name: '__Host-session',
              secret: process.env.SESSION_SECRET,
              cookie: {
                secure: true,
                httpOnly: true,
                sameSite: 'lax',
                maxAge: 3600000
              }
            }));
            """
        case "API Security":
            conceptualAbuse = "Reflecting arbitrary `Origin` headers alongside `Access-Control-Allow-Credentials: true` weakens the Same-Origin Policy and permits untrusted origins to read authenticated API responses."
            codePattern = """
            // Secure CORS Allowlist Pattern
            const ALLOWED_ORIGINS = new Set(['https://app.example.com']);
            const origin = req.headers.origin;
            if (ALLOWED_ORIGINS.has(origin)) {
              res.setHeader('Access-Control-Allow-Origin', origin);
              res.setHeader('Access-Control-Allow-Credentials', 'true');
              res.setHeader('Vary', 'Origin');
            }
            """
        default:
            conceptualAbuse = finding.impact
            codePattern = """
            # Nginx / Web Server Hardening Example
            server_tokens off;
            autoindex off;
            location ~ /\\.(env|git) {
                deny all;
                return 404;
            }
            """
        }

        let fpAssessment: String
        switch finding.status {
        case .verified:
            fpAssessment = "Low false-positive likelihood: Sentinel captured direct, deterministic HTTP evidence (\(finding.confidence.rawValue) confidence). Verify whether a reverse proxy or CDN applies different rules on other routes."
        case .suspected:
            fpAssessment = "Moderate false-positive likelihood: Flagged via non-destructive behavioral/heuristic indicators. Review backend source code or test in a local staging environment to confirm."
        case .manualReviewRequired:
            fpAssessment = "Requires human verification: Automated scanning identified an architectural or parameter indicator that depends on application business logic."
        case .informational, .incomplete:
            fpAssessment = "Informational observation / incomplete check."
        }

        let priority: String
        switch finding.severity {
        case .critical:
            priority = "P0 — Immediate (Remediate within 24 hours; blocks release)"
        case .high:
            priority = "P1 — High Priority (Remediate within 3–7 days)"
        case .medium:
            priority = "P2 — Scheduled (Remediate in current sprint)"
        case .low, .informational:
            priority = "P3 — Defense-in-Depth Hardening"
        }

        let validationGuide = """
        1. Target Environment: Use your local development server or an explicitly authorized staging environment.
        2. Reproduce Safely: \(finding.safeReproduction)
        3. Apply Fix: \(finding.remediation)
        4. Verify Resolution: Re-run Sentinel against `\(finding.affectedURL)` and confirm "\(finding.title)" no longer appears in the findings list.
        """

        let limitations = "Sentinel performs strictly non-destructive, scope-enforced checks. It does not brute-force credentials, exploit state-changing workflows, or exfiltrate database contents."

        return AIAnalysisResult(
            plainLanguageSummary: summary,
            relatedFindingsAnalysis: correlations.joined(separator: "\n\n"),
            conceptualAbuseScenario: conceptualAbuse,
            falsePositiveAssessment: fpAssessment,
            controlledValidationProcedure: validationGuide,
            secureCodePattern: codePattern,
            remediationPriority: priority,
            testingLimitations: limitations,
            generatedByModel: "Sentinel Local Deterministic Analyst v1.0"
        )
    }

    public static func requestEnhancedLLMAnalysis(
        for finding: VulnerabilityFinding,
        allFindings: [VulnerabilityFinding],
        provider: AIProvider,
        customModel: String? = nil
    ) async throws -> AIAnalysisResult {
        let baseAnalysis = generateDeterministicAnalysis(for: finding, allFindings: allFindings)
        guard let apiKey = KeychainHelper.loadKey(for: provider), !apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return baseAnalysis
        }

        let model = (customModel?.isEmpty == false) ? customModel! : provider.defaultModel
        let redactedEvidence = ScannerBridge.redact(finding.evidence)

        let prompt = """
        You are a senior defensive application security analyst reviewing a verified/suspected scanner finding.
        NEVER invent scanner evidence. Rely strictly on the provided finding data.
        Provide a concise, actionable defensive explanation and remediation review (3 short paragraphs max).

        Finding Title: \(finding.title)
        Category: \(finding.category) (\(finding.owaspCategory))
        Severity: \(finding.severity.rawValue) | Confidence: \(finding.confidence.rawValue) | Status: \(finding.status.rawValue)
        Affected URL: \(finding.affectedURL)
        Affected Parameter/Component: \(finding.affectedParameter)
        Redacted Scanner Evidence: \(redactedEvidence)
        Technical Explanation: \(finding.technicalExplanation)
        """

        var request: URLRequest
        switch provider {
        case .openAI:
            guard let url = URL(string: "https://api.openai.com/v1/chat/completions") else { return baseAnalysis }
            request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            let body: [String: Any] = [
                "model": model,
                "messages": [
                    ["role": "system", "content": "You are a defensive cybersecurity auditor. Never fabricate evidence."],
                    ["role": "user", "content": prompt]
                ],
                "temperature": 0.2
            ]
            request.httpBody = try JSONSerialization.data(withJSONObject: body)

        case .anthropic:
            guard let url = URL(string: "https://api.anthropic.com/v1/messages") else { return baseAnalysis }
            request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
            request.setValue("2023-06-01", forHTTPHeaderField: "anthropic-version")
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            let body: [String: Any] = [
                "model": model,
                "max_tokens": 500,
                "messages": [
                    ["role": "user", "content": prompt]
                ]
            ]
            request.httpBody = try JSONSerialization.data(withJSONObject: body)

        case .gemini:
            guard let url = URL(string: "https://generativelanguage.googleapis.com/v1beta/models/\(model):generateContent?key=\(apiKey)") else {
                return baseAnalysis
            }
            request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            let body: [String: Any] = [
                "contents": [
                    ["parts": [["text": prompt]]]
                ]
            ]
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        }

        request.timeoutInterval = 15
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResp = response as? HTTPURLResponse, (200...299).contains(httpResp.statusCode) else {
            return baseAnalysis
        }

        var llmText: String?
        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            if let choices = json["choices"] as? [[String: Any]],
               let message = choices.first?["message"] as? [String: Any],
               let content = message["content"] as? String {
                llmText = content
            } else if let contentArr = json["content"] as? [[String: Any]],
                      let text = contentArr.first?["text"] as? String {
                llmText = text
            } else if let candidates = json["candidates"] as? [[String: Any]],
                      let content = candidates.first?["content"] as? [String: Any],
                      let parts = content["parts"] as? [[String: Any]],
                      let text = parts.first?["text"] as? String {
                llmText = text
            }
        }

        var enhanced = baseAnalysis
        if let llmText, !llmText.isEmpty {
            enhanced.plainLanguageSummary = baseAnalysis.plainLanguageSummary + "\n\n[AI Provider Commentary (\(provider.rawValue) - \(model))]:\n" + llmText
            enhanced.generatedByModel = "\(provider.rawValue) (\(model)) + Sentinel Deterministic Engine"
        }
        return enhanced
    }
}
