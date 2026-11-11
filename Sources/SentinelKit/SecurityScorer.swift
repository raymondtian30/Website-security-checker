import Foundation

public struct SecurityScorer {
    public static func calculateScore(
        findings: [VulnerabilityFinding],
        completedChecks: Int,
        totalChecks: Int
    ) -> SecurityScoreBreakdown {
        let activeFindings = findings.filter { !$0.isResolved }

        let criticalCount = activeFindings.filter { $0.severity == .critical && $0.status != .incomplete }.count
        let highCount = activeFindings.filter { $0.severity == .high && $0.status != .incomplete }.count
        let mediumCount = activeFindings.filter { $0.severity == .medium && $0.status != .incomplete }.count
        let lowCount = activeFindings.filter { $0.severity == .low && $0.status != .incomplete }.count
        let infoCount = activeFindings.filter { $0.severity == .informational || $0.status == .informational }.count

        let verifiedCount = activeFindings.filter { $0.status == .verified }.count
        let suspectedCount = activeFindings.filter { $0.status == .suspected }.count
        let manualReviewCount = activeFindings.filter { $0.status == .manualReviewRequired }.count
        let incompleteCount = activeFindings.filter { $0.status == .incomplete }.count

        let safeTotalChecks = max(1, totalChecks)
        let coveragePercent = min(100.0, max(0.0, (Double(completedChecks) / Double(safeTotalChecks)) * 100.0))

        // Group active non-informational findings by rootCauseKey to avoid double-counting site-wide issues
        var groupedByRootCause: [String: [VulnerabilityFinding]] = [:]
        for f in activeFindings where f.status != .informational && f.status != .incomplete && f.severity != .informational {
            let key = f.rootCauseKey.isEmpty ? f.id : f.rootCauseKey
            groupedByRootCause[key, default: []].append(f)
        }

        var totalPenalty = 0.0
        var hasVerifiedCritical = false
        var factors: [String] = []

        for (_, group) in groupedByRootCause {
            // Take the highest-impact representative finding in this root cause group
            guard let primary = group.max(by: { a, b in
                if a.severity != b.severity { return a.severity < b.severity }
                return a.confidence < b.confidence
            }) else { continue }

            let baseWeight: Double
            switch primary.severity {
            case .critical: baseWeight = 28.0
            case .high: baseWeight = 16.0
            case .medium: baseWeight = 7.5
            case .low: baseWeight = 2.5
            case .informational: baseWeight = 0.0
            }

            let statusMultiplier: Double
            switch primary.status {
            case .verified: statusMultiplier = 1.0
            case .suspected: statusMultiplier = 0.55
            case .manualReviewRequired: statusMultiplier = 0.25
            case .informational, .incomplete: statusMultiplier = 0.0
            }

            let confidenceMultiplier: Double
            switch primary.confidence {
            case .high: confidenceMultiplier = 1.0
            case .medium: confidenceMultiplier = 0.75
            case .low: confidenceMultiplier = 0.45
            }

            // Mild exposure multiplier when the same root issue affects multiple endpoints (capped at 1.25x)
            let uniqueEndpoints = Set(group.map(\.affectedURL)).count
            let exposureMultiplier = min(1.25, 1.0 + 0.05 * Double(max(0, uniqueEndpoints - 1)))

            let deduction = baseWeight * statusMultiplier * confidenceMultiplier * exposureMultiplier
            totalPenalty += deduction

            if primary.severity == .critical && primary.status == .verified {
                hasVerifiedCritical = true
            }
        }

        var rawScore = Int((100.0 - totalPenalty).rounded())
        rawScore = max(0, min(100, rawScore))

        // Critical failure cap: Any verified Critical vulnerability caps the score at 69 (Grade D)
        if hasVerifiedCritical && rawScore > 69 {
            rawScore = 69
            factors.append("Score capped at 69 (Grade D) due to at least one Verified Critical vulnerability.")
        }

        // Coverage accountability: Missing scan coverage is never treated as passing
        if coveragePercent < 100.0 {
            factors.append(String(format: "Scan coverage is %.0f%% (%d/%d modules completed). Untested modules are not assumed passing.", coveragePercent, completedChecks, safeTotalChecks))
        } else {
            factors.append("100% of configured security check modules completed.")
        }

        if groupedByRootCause.count < (criticalCount + highCount + mediumCount + lowCount) {
            let totalRaw = criticalCount + highCount + mediumCount + lowCount
            factors.append("Deduplicated \(totalRaw) endpoint findings into \(groupedByRootCause.count) unique root causes to prevent double-counting.")
        }

        if criticalCount > 0 {
            factors.append("\(criticalCount) Critical finding(s) detected — immediate remediation required.")
        }
        if highCount > 0 {
            factors.append("\(highCount) High-severity finding(s) substantially reduced the security score.")
        }
        if verifiedCount == 0 && suspectedCount == 0 && coveragePercent == 100.0 {
            factors.append("No verified or suspected vulnerabilities detected across completed checks.")
        }

        let (grade, meaning) = gradeAndMeaning(for: rawScore, coveragePercent: coveragePercent)

        let explanation = """
        Sentinel calculates security scores starting from a baseline of 100 points:
        1. Root-Cause Deduplication: Findings caused by the same underlying issue (e.g., a missing header across multiple URLs) are grouped by Root Cause Key with a capped exposure factor (up to 1.25x).
        2. Severity & Verification Weighting: Base deductions (Critical: 28, High: 16, Medium: 7.5, Low: 2.5, Info: 0) are multiplied by Verification Status (Verified: 1.0x, Suspected: 0.55x, Manual Review: 0.25x) and Confidence (High: 1.0x, Medium: 0.75x, Low: 0.45x).
        3. Critical Failure Cap: Any Verified Critical vulnerability caps the maximum possible score at 69 (Grade D).
        4. Coverage Separation: Scan coverage is tracked independently (\(Int(coveragePercent))%). Incomplete or cancelled checks are never treated as passing.
        """

        return SecurityScoreBreakdown(
            overallScore: rawScore,
            letterGrade: grade,
            postureMeaning: meaning,
            coveragePercent: coveragePercent,
            criticalCount: criticalCount,
            highCount: highCount,
            mediumCount: mediumCount,
            lowCount: lowCount,
            infoCount: infoCount,
            verifiedCount: verifiedCount,
            suspectedCount: suspectedCount,
            manualReviewCount: manualReviewCount,
            incompleteCount: incompleteCount,
            deduplicatedRootCauses: groupedByRootCause.count,
            scoringFactors: factors,
            algorithmExplanation: explanation
        )
    }

    public static func gradeAndMeaning(for score: Int, coveragePercent: Double) -> (String, String) {
        let baseGrade: String
        let baseMeaning: String
        switch score {
        case 95...100:
            baseGrade = "A+"
            baseMeaning = "Excellent"
        case 90...94:
            baseGrade = "A"
            baseMeaning = "Very strong"
        case 85...89:
            baseGrade = "B+"
            baseMeaning = "Good"
        case 80...84:
            baseGrade = "B"
            baseMeaning = "Above average"
        case 75...79:
            baseGrade = "C+"
            baseMeaning = "Moderate"
        case 70...74:
            baseGrade = "C"
            baseMeaning = "Needs improvement"
        case 60...69:
            baseGrade = "D"
            baseMeaning = "Weak"
        default:
            baseGrade = "F"
            baseMeaning = "Poor"
        }

        if coveragePercent < 50.0 {
            return (baseGrade + "*", baseMeaning + " (Partial Coverage)")
        }
        return (baseGrade, baseMeaning)
    }

    public static func evaluateVisitorSafety(findings: [VulnerabilityFinding], overallScore: Int) -> VisitorSafetyEvaluation {
        let active = findings.filter { !$0.isResolved && $0.status != .incomplete }
        let malwareFindings = active.filter {
            $0.category == "Malware & Visitor Safety" || $0.rootCauseKey.hasPrefix("MALWARE_")
        }
        let clientRiskFindings = active.filter {
            $0.category == "Cross-Site Scripting (XSS)" ||
            $0.rootCauseKey == "TLS_MIXED_CONTENT" ||
            $0.rootCauseKey == "TLS_INVALID_CERTIFICATE" ||
            $0.rootCauseKey == "AUTH_HTTP_LOGIN_FORM"
        }

        var penalty = 0
        for m in malwareFindings {
            switch m.severity {
            case .critical: penalty += 45
            case .high: penalty += 32
            case .medium: penalty += 18
            case .low, .informational: penalty += 8
            }
        }
        for c in clientRiskFindings {
            switch c.severity {
            case .critical: penalty += 18
            case .high: penalty += 12
            case .medium: penalty += 5
            case .low, .informational: penalty += 2
            }
        }

        // Factor in general security hygiene lightly if no active malware is present
        if malwareFindings.isEmpty && overallScore < 75 {
            penalty += (75 - overallScore) / 3
        }

        var safetyScore = max(1, min(100, 100 - penalty))
        if !malwareFindings.isEmpty && safetyScore > 45 {
            safetyScore = 35 // Any active malware forces an F (Unsafe to Visit) rating
        }

        let safetyGrade: String
        switch safetyScore {
        case 95...100: safetyGrade = "A+"
        case 90...94: safetyGrade = "A"
        case 80...89: safetyGrade = "B"
        case 70...79: safetyGrade = "C"
        case 60...69: safetyGrade = "D"
        default: safetyGrade = "F"
        }

        let isSafe = malwareFindings.isEmpty && safetyScore >= 70
        let verdictLabel: String
        let verdictDescription: String

        if !malwareFindings.isEmpty {
            verdictLabel = "UNSAFE TO VISIT — MALWARE DETECTED"
            verdictDescription = "DANGER: Sentinel detected \(malwareFindings.count) active malware threat(s) on this website (Visitor Safety Score: \(safetyScore)/100, Grade \(safetyGrade)). Visiting this website can expose visitors to credential/card theft, browser cryptojacking, or drive-by exploit payloads."
        } else if safetyScore >= 85 {
            verdictLabel = "SAFE TO VISIT"
            verdictDescription = "No web malware, skimmers, cryptojackers, hidden exploit iframes, or drive-by download payloads were detected (Visitor Safety Score: \(safetyScore)/100, Grade \(safetyGrade))."
        } else if safetyScore >= 70 {
            verdictLabel = "SAFE TO VISIT (WITH MINOR WARNINGS)"
            verdictDescription = "No active malware payloads were detected (Visitor Safety Score: \(safetyScore)/100, Grade \(safetyGrade)), though some transport or client-side security configurations should be hardened."
        } else {
            verdictLabel = "CAUTION ADVISED — UNSAFE TRANSPORT / CLIENT RISKS"
            verdictDescription = "While no explicit malware payloads were found, severe transport or client-side vulnerabilities make entering sensitive data on this website risky (Visitor Safety Score: \(safetyScore)/100, Grade \(safetyGrade))."
        }

        return VisitorSafetyEvaluation(
            safetyScore: safetyScore,
            safetyGrade: safetyGrade,
            isSafeToVisit: isSafe,
            verdictLabel: verdictLabel,
            verdictDescription: verdictDescription,
            detectedMalware: malwareFindings
        )
    }

    public static func compareScans(baseline: ScanRecord, current: ScanRecord) -> ScanComparisonResult {
        let baselineKeys = Set(baseline.findings.filter { $0.status != .incomplete }.map { "\($0.rootCauseKey)|\($0.affectedParameter)" })
        let currentKeys = Set(current.findings.filter { $0.status != .incomplete }.map { "\($0.rootCauseKey)|\($0.affectedParameter)" })

        let newFindings = current.findings.filter { f in
            f.status != .incomplete && !baselineKeys.contains("\(f.rootCauseKey)|\(f.affectedParameter)")
        }
        let resolvedFindings = baseline.findings.filter { f in
            f.status != .incomplete && !currentKeys.contains("\(f.rootCauseKey)|\(f.affectedParameter)")
        }
        let persistingFindings = current.findings.filter { f in
            f.status != .incomplete && baselineKeys.contains("\(f.rootCauseKey)|\(f.affectedParameter)")
        }

        return ScanComparisonResult(
            baselineScan: baseline,
            currentScan: current,
            scoreDelta: current.scoreBreakdown.overallScore - baseline.scoreBreakdown.overallScore,
            coverageDelta: current.scoreBreakdown.coveragePercent - baseline.scoreBreakdown.coveragePercent,
            newFindings: newFindings,
            resolvedFindings: resolvedFindings,
            persistingFindings: persistingFindings
        )
    }
}
