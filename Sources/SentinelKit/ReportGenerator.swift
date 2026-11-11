import Foundation
import AppKit
import CoreGraphics
import CoreText

public struct ReportGenerator {
    public static func generateJSONReport(for scan: ScanRecord) throws -> Data {
        var sanitizedScan = scan
        sanitizedScan.findings = scan.findings.map { f in
            var copy = f
            copy.evidence = ScannerBridge.redact(f.evidence)
            return copy
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(sanitizedScan)
    }

    public static func generateHTMLReport(for scan: ScanRecord) -> String {
        let df = ISO8601DateFormatter()
        let dateStr = df.string(from: scan.timestamp)
        let sb = scan.scoreBreakdown

        func esc(_ s: String) -> String {
            s.replacingOccurrences(of: "&", with: "&amp;")
             .replacingOccurrences(of: "<", with: "&lt;")
             .replacingOccurrences(of: ">", with: "&gt;")
             .replacingOccurrences(of: "\"", with: "&quot;")
        }

        var findingsHTML = ""
        for f in scan.findings {
            let redactedEv = ScannerBridge.redact(f.evidence)
            let badgeColor: String
            switch f.severity {
            case .critical: badgeColor = "#dc2626"
            case .high: badgeColor = "#ea580c"
            case .medium: badgeColor = "#d97706"
            case .low: badgeColor = "#0284c7"
            case .informational: badgeColor = "#64748b"
            }

            findingsHTML += """
            <div class="finding-card">
                <div class="finding-header">
                    <span class="badge" style="background:\(badgeColor);">\(esc(f.severity.rawValue.uppercased()))</span>
                    <span class="status-tag">\(esc(f.status.displayLabel))</span>
                    <span class="status-tag">Confidence: \(esc(f.confidence.rawValue))</span>
                    <span class="status-tag">CVSS: \(String(format: "%.1f", f.cvssScore))</span>
                    <span class="status-tag">\(esc(f.owaspCategory))</span>
                    \(f.isResolved ? "<span class=\"status-tag\" style=\"background:#059669;color:#fff;\">RESOLVED</span>" : "")
                </div>
                <h3>\(esc(f.title))</h3>
                <p><strong>Affected URL:</strong> <code>\(esc(f.affectedURL))</code> &nbsp;|&nbsp; <strong>Component:</strong> <code>\(esc(f.affectedParameter))</code></p>
                <p><strong>Technical Explanation:</strong> \(esc(f.technicalExplanation))</p>
                <p><strong>Security Impact:</strong> \(esc(f.impact))</p>
                <div class="evidence-box"><strong>Supporting Evidence (Redacted):</strong><pre>\(esc(redactedEv))</pre></div>
                <p><strong>Safe Validation Procedure:</strong><br>\(esc(f.safeReproduction).replacingOccurrences(of: "\n", with: "<br>"))</p>
                <p><strong>Recommended Remediation:</strong><br>\(esc(f.remediation).replacingOccurrences(of: "\n", with: "<br>"))</p>
            </div>
            """
        }

        if findingsHTML.isEmpty {
            findingsHTML = "<p>No vulnerabilities or configuration issues were identified across the completed scan modules.</p>"
        }

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Website Security Assessment Report — \(esc(scan.targetDomain))</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 32px; line-height: 1.55; }
                .container { max-width: 1040px; margin: 0 auto; }
                .header { background: #1e293b; padding: 24px; border-radius: 12px; border: 1px solid #334155; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }
                .score-box { text-align: center; background: #0f172a; padding: 18px 28px; border-radius: 10px; border: 1px solid #475569; }
                .score-num { font-size: 42px; font-weight: 800; color: #38bdf8; }
                .grade { font-size: 24px; font-weight: 700; color: #f8fafc; }
                .grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }
                .stat-card { background: #1e293b; padding: 16px; border-radius: 10px; border: 1px solid #334155; text-align: center; }
                .section { background: #1e293b; padding: 22px; border-radius: 12px; border: 1px solid #334155; margin-bottom: 24px; }
                .finding-card { background: #0f172a; padding: 18px; border-radius: 10px; border: 1px solid #334155; margin-bottom: 16px; }
                .finding-header { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; align-items: center; }
                .badge { padding: 4px 10px; border-radius: 6px; color: white; font-weight: 700; font-size: 12px; }
                .status-tag { padding: 3px 8px; border-radius: 6px; background: #334155; color: #cbd5e1; font-size: 12px; }
                .evidence-box { background: #020617; padding: 12px; border-radius: 8px; border: 1px solid #1e293b; overflow-x: auto; margin: 10px 0; }
                pre, code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; color: #93c5fd; white-space: pre-wrap; word-break: break-all; }
                h1, h2, h3 { color: #f8fafc; margin-top: 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div>
                        <h1>Website Security Audit Report</h1>
                        <p><strong>Target:</strong> \(esc(scan.targetURL)) (\(esc(scan.targetDomain)))</p>
                        <p><strong>Assessment Date:</strong> \(esc(dateStr)) &nbsp;|&nbsp; <strong>Status:</strong> \(esc(scan.status))</p>
                        <p><strong>Scan Coverage:</strong> \(String(format: "%.0f%%", sb.coveragePercent)) &nbsp;|&nbsp; <strong>Endpoints Examined:</strong> \(scan.endpointsExamined)</p>
                    </div>
                    <div class="score-box">
                        <div class="score-num">\(sb.overallScore)/100</div>
                        <div class="grade">Grade \(esc(sb.letterGrade)) — \(esc(sb.postureMeaning))</div>
                    </div>
                </div>

                <div class="grid">
                    <div class="stat-card"><h2 style="color:#ef4444;">\(sb.criticalCount)</h2><div>Critical</div></div>
                    <div class="stat-card"><h2 style="color:#f97316;">\(sb.highCount)</h2><div>High</div></div>
                    <div class="stat-card"><h2 style="color:#eab308;">\(sb.mediumCount)</h2><div>Medium</div></div>
                    <div class="stat-card"><h2 style="color:#38bdf8;">\(sb.lowCount)</h2><div>Low</div></div>
                    <div class="stat-card"><h2 style="color:#94a3b8;">\(sb.infoCount)</h2><div>Informational</div></div>
                </div>

                <div class="section">
                    <h2>Executive Summary & Scoring Factors</h2>
                    <ul>
                        \(sb.scoringFactors.map { "<li>\(esc($0))</li>" }.joined(separator: "\n"))
                    </ul>
                    <p><strong>Configuration:</strong> Intensity: \(esc(scan.configuration.intensity)), Rate Limit: \(scan.configuration.maxRequestsPerSecond) req/s, Max Duration: \(scan.configuration.maxDurationSeconds)s.</p>
                    <p><strong>Testing Limitations:</strong> Assessment performed using non-destructive, scope-enforced indicator checks. Untested or out-of-scope components are not assumed secure. Sensitive tokens/secrets in evidence have been automatically redacted.</p>
                </div>

                <div class="section">
                    <h2>Detailed Security Findings (\(scan.findings.count))</h2>
                    \(findingsHTML)
                </div>
            </div>
        </body>
        </html>
        """
    }

    public static func generatePDFReport(for scan: ScanRecord) -> Data {
        let pdfData = NSMutableData()
        var mediaBox = CGRect(x: 0, y: 0, width: 612, height: 792) // US Letter

        guard let consumer = CGDataConsumer(data: pdfData as CFMutableData),
              let context = CGContext(consumer: consumer, mediaBox: &mediaBox, nil) else {
            return Data()
        }

        let df = ISO8601DateFormatter()
        let dateStr = df.string(from: scan.timestamp)
        let sb = scan.scoreBreakdown

        var lines: [String] = [
            "WEBSITE SECURITY CHECKER — SECURITY AUDIT REPORT",
            "======================================================================",
            "Target URL:          \(scan.targetURL)",
            "Target Domain:       \(scan.targetDomain)",
            "Assessment Date:     \(dateStr)",
            "Scan Status:         \(scan.status)",
            "Overall Score:       \(sb.overallScore) / 100 (Grade \(sb.letterGrade) - \(sb.postureMeaning))",
            "Scan Coverage:       \(String(format: "%.0f%%", sb.coveragePercent)) | Endpoints Examined: \(scan.endpointsExamined)",
            "Scan Configuration:  Intensity=\(scan.configuration.intensity), RateLimit=\(scan.configuration.maxRequestsPerSecond) rps",
            "",
            "VULNERABILITY BREAKDOWN",
            "----------------------------------------------------------------------",
            "Critical: \(sb.criticalCount)  |  High: \(sb.highCount)  |  Medium: \(sb.mediumCount)  |  Low: \(sb.lowCount)  |  Info: \(sb.infoCount)",
            "Verified: \(sb.verifiedCount)  |  Suspected: \(sb.suspectedCount)  |  Manual Review: \(sb.manualReviewCount)",
            "",
            "KEY SCORING FACTORS",
            "----------------------------------------------------------------------"
        ]
        for factor in sb.scoringFactors {
            lines.append("• \(factor)")
        }
        lines.append("")
        lines.append("TESTING LIMITATIONS")
        lines.append("----------------------------------------------------------------------")
        lines.append("Non-destructive assessment within authorized scope. Sensitive values are")
        lines.append("redacted ([REDACTED]). Untested modules are never treated as passing.")
        lines.append("")
        lines.append("DETAILED FINDINGS (\(scan.findings.count))")
        lines.append("======================================================================")

        for (idx, f) in scan.findings.enumerated() {
            let redactedEv = ScannerBridge.redact(f.evidence)
            lines.append("")
            lines.append("[\(idx + 1)] [\(f.severity.rawValue.uppercased())] \(f.title)")
            lines.append("    Status: \(f.status.displayLabel) | Confidence: \(f.confidence.rawValue) | CVSS: \(String(format: "%.1f", f.cvssScore))")
            lines.append("    Category: \(f.category) | OWASP: \(f.owaspCategory)")
            lines.append("    URL: \(f.affectedURL) | Parameter: \(f.affectedParameter)")
            lines.append("    Explanation: \(f.technicalExplanation)")
            lines.append("    Impact: \(f.impact)")
            lines.append("    Evidence (Redacted): \(redactedEv.replacingOccurrences(of: "\n", with: " "))")
            lines.append("    Safe Validation: \(f.safeReproduction.replacingOccurrences(of: "\n", with: " "))")
            lines.append("    Remediation: \(f.remediation.replacingOccurrences(of: "\n", with: " "))")
            lines.append("----------------------------------------------------------------------")
        }

        // Wrap long lines cleanly at 88 chars and paginate at 52 lines per page
        var wrappedLines: [String] = []
        for rawLine in lines {
            if rawLine.count <= 88 {
                wrappedLines.append(rawLine)
            } else {
                var rem = rawLine
                while rem.count > 88 {
                    let splitIdx = rem.index(rem.startIndex, offsetBy: 88)
                    wrappedLines.append(String(rem[..<splitIdx]))
                    rem = "    " + String(rem[splitIdx...])
                }
                if !rem.isEmpty {
                    wrappedLines.append(rem)
                }
            }
        }

        let linesPerPage = 52
        let font = CTFontCreateWithName("Menlo" as CFString, 9.5, nil)
        let color = CGColor(red: 0.1, green: 0.12, blue: 0.18, alpha: 1.0)

        var lineIndex = 0
        while lineIndex < wrappedLines.count {
            context.beginPDFPage(nil)
            context.textMatrix = .identity

            let endLine = min(lineIndex + linesPerPage, wrappedLines.count)
            var yPos: CGFloat = 748.0

            for i in lineIndex..<endLine {
                let text = wrappedLines[i]
                let attrs: [CFString: Any] = [
                    kCTFontAttributeName: font,
                    kCTForegroundColorAttributeName: color
                ]
                if let attrStr = CFAttributedStringCreate(kCFAllocatorDefault, text as CFString, attrs as CFDictionary) {
                    let ctLine = CTLineCreateWithAttributedString(attrStr)
                    context.textPosition = CGPoint(x: 42.0, y: yPos)
                    CTLineDraw(ctLine, context)
                }
                yPos -= 13.2
            }

            context.endPDFPage()
            lineIndex = endLine
        }

        context.closePDF()
        return pdfData as Data
    }
}
