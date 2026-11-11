import SwiftUI
import Charts
import SentinelKit

public struct DashboardView: View {
    @ObservedObject var vm: AppViewModel

    public init(vm: AppViewModel) {
        self.vm = vm
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                headerBar

                if vm.isScanning {
                    liveScanBanner
                }

                if let scan = vm.activeScan {
                    scoreAndSeverityRow(scan: scan)
                    malwareVisitorSafetyCard(scan: scan)
                    chartsAndPrioritiesRow(scan: scan)
                } else {
                    emptyStateCard
                }
            }
            .padding(24)
        }
        .background(SentinelTheme.bgPrimary)
    }

    private var headerBar: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text("Security Overview")
                        .font(.system(size: 25, weight: .bold))
                        .foregroundStyle(.white)
                    HelpTooltip(
                        "Security Overview Dashboard",
                        explanation: "Shows your website's 0–100 Security Posture Score, 1–100 Visitor Safety & Malware Rating, severity breakdown, and top prioritized fixes."
                    )
                }
                if let scan = vm.activeScan {
                    Text("\(scan.targetURL) • Assessed \(scan.timestamp.formatted(date: .abbreviated, time: .shortened))")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                } else {
                    Text("No active scan loaded. Use 'Step-by-Step Guide' or 'New Scan' to begin.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            .layoutPriority(1)

            Spacer()

            Button {
                vm.showStepByStepGuide = true
            } label: {
                Label("Step-by-Step Guide", systemImage: "book.pages.fill")
            }
            .buttonStyle(.bordered)

            if let scan = vm.activeScan {
                Menu {
                    ForEach(ReportFormat.allCases, id: \.rawValue) { fmt in
                        Button("Export \(fmt.rawValue) Report") {
                            vm.exportReport(for: scan, format: fmt)
                        }
                    }
                } label: {
                    Label("Export Report", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.bordered)
            }

            Button {
                vm.selectedTab = .scanConfig
            } label: {
                Label("New Scan", systemImage: "play.fill")
            }
            .buttonStyle(.borderedProminent)
            .tint(SentinelTheme.accentCyan)
        }
    }

    private var liveScanBanner: some View {
        SectionCard(title: "Live Security Scan Running", icon: "waveform.path.ecg") {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Module: \(vm.liveProgress.currentModule)")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.white)
                    Spacer()
                    Text("\(Int(vm.liveProgress.coveragePercent))% • \(vm.liveProgress.endpointsExamined) Endpoints • \(vm.liveProgress.findingsCount) Findings")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                ProgressView(value: vm.liveProgress.coveragePercent, total: 100.0)
                    .tint(SentinelTheme.accentCyan)
                HStack(spacing: 10) {
                    Button(vm.isPaused ? "Resume" : "Pause") {
                        vm.togglePauseScan()
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)

                    Button(role: .destructive) {
                        vm.emergencyStopScan()
                    } label: {
                        Label("Emergency Stop", systemImage: "xmark.octagon.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                    .controlSize(.small)
                }
            }
        }
    }

    private func scoreAndSeverityRow(scan: ScanRecord) -> some View {
        let sb = scan.scoreBreakdown
        return HStack(alignment: .top, spacing: 16) {
            // Protected Score Card — never shrinks into unreadability
            SectionCard(
                title: "Overall Security Score",
                icon: "gauge.with.dots.needle.67percent",
                helpText: "Scored 0–100 based on deduplicated root-cause vulnerabilities weighted by severity, confidence, and verification status. Any Verified Critical flaw caps the score at 69 (Grade D)."
            ) {
                HStack(spacing: 20) {
                    ZStack {
                        Circle()
                            .stroke(Color.white.opacity(0.08), lineWidth: 11)
                            .frame(width: 106, height: 106)
                        Circle()
                            .trim(from: 0, to: CGFloat(sb.overallScore) / 100.0)
                            .stroke(
                                SentinelTheme.gradeColor(sb.overallScore),
                                style: StrokeStyle(lineWidth: 11, lineCap: .round)
                            )
                            .rotationEffect(.degrees(-90))
                            .frame(width: 106, height: 106)
                        VStack(spacing: 1) {
                            Text("\(sb.overallScore)")
                                .font(.system(size: 30, weight: .heavy, design: .rounded))
                                .foregroundStyle(.white)
                            Text("/ 100")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .fixedSize()

                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 10) {
                            Text("Grade \(sb.letterGrade)")
                                .font(.system(size: 20, weight: .bold, design: .rounded))
                                .lineLimit(1)
                                .fixedSize(horizontal: true, vertical: false)
                                .padding(.horizontal, 11)
                                .padding(.vertical, 4)
                                .background(SentinelTheme.gradeColor(sb.overallScore).opacity(0.2))
                                .foregroundStyle(SentinelTheme.gradeColor(sb.overallScore))
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                            Text(sb.postureMeaning)
                                .font(.headline)
                                .foregroundStyle(.white)
                                .lineLimit(1)
                                .fixedSize(horizontal: true, vertical: false)
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            HStack(spacing: 6) {
                                Text("Scan Coverage: \(String(format: "%.0f%%", sb.coveragePercent))")
                                    .font(.caption.weight(.medium))
                                    .foregroundStyle(sb.coveragePercent == 100 ? .green : .orange)
                                    .fixedSize(horizontal: true, vertical: false)
                                HelpTooltip(
                                    "Scan Coverage Percentage",
                                    explanation: "Percentage of configured security modules that finished executing. Cancelled or timed-out checks are marked Incomplete and never counted as passing."
                                )
                            }
                            ProgressView(value: sb.coveragePercent, total: 100.0)
                                .tint(sb.coveragePercent == 100 ? .green : .orange)
                        }

                        HStack(spacing: 6) {
                            Text("Verified: \(sb.verifiedCount) • Suspected: \(sb.suspectedCount) • Root Causes: \(sb.deduplicatedRootCauses)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .fixedSize(horizontal: true, vertical: false)
                            HelpTooltip(
                                "Root-Cause Deduplication",
                                explanation: "If the same missing header or misconfiguration appears on 10 pages, Sentinel groups them into 1 Root Cause so your score isn't unfairly penalized 10 times."
                            )
                        }
                    }
                }
            }
            .frame(minWidth: 425, idealWidth: 435, maxWidth: 450)
            .layoutPriority(2)

            // Flexible Secondary Severity Counter Boxes — shrink first on window resize
            VStack(spacing: 12) {
                HStack(spacing: 8) {
                    severityCounterCard(title: "Critical", count: sb.criticalCount, severity: .critical)
                    severityCounterCard(title: "High", count: sb.highCount, severity: .high)
                    severityCounterCard(title: "Medium", count: sb.mediumCount, severity: .medium)
                    severityCounterCard(title: "Low", count: sb.lowCount, severity: .low)
                    severityCounterCard(title: "Info", count: sb.infoCount, severity: .informational)
                }
                SectionCard {
                    ViewThatFits(in: .horizontal) {
                        HStack {
                            Label("Endpoints: \(scan.endpointsExamined)", systemImage: "network")
                            Spacer(minLength: 8)
                            Label("Status: \(scan.status)", systemImage: "checkmark.seal.fill")
                            Spacer(minLength: 8)
                            Label("Duration: \(scan.durationSeconds)s", systemImage: "timer")
                        }
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)

                        Text("Endpoints: \(scan.endpointsExamined) • Status: \(scan.status) • \(scan.durationSeconds)s")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .minimumScaleFactor(0.8)
                    }
                }
            }
            .frame(minWidth: 240, maxWidth: .infinity)
            .layoutPriority(0)
        }
    }

    private func malwareVisitorSafetyCard(scan: ScanRecord) -> some View {
        let safety = SecurityScorer.evaluateVisitorSafety(
            findings: scan.findings,
            overallScore: scan.scoreBreakdown.overallScore
        )
        let color = SentinelTheme.gradeColor(safety.safetyScore)

        return SectionCard(
            title: "Website Malware & Visitor Safety Rating",
            icon: safety.isSafeToVisit ? "checkmark.shield.fill" : "ladybug.fill",
            helpText: "Evaluates whether this website is safe for users to visit on a 1–100 scale (Grade F–A+). Checks for Magecart card skimmers, cryptojackers, obfuscated JS droppers, hidden exploit iframes, webshells, and drive-by downloads."
        ) {
            HStack(alignment: .center, spacing: 16) {
                HStack(spacing: 10) {
                    Text("\(safety.safetyScore)/100")
                        .font(.system(size: 24, weight: .heavy, design: .rounded))
                        .foregroundStyle(color)
                        .fixedSize()

                    Text("Grade \(safety.safetyGrade)")
                        .font(.system(size: 15, weight: .bold, design: .rounded))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background(color.opacity(0.2))
                        .foregroundStyle(color)
                        .clipShape(RoundedRectangle(cornerRadius: 7))
                        .fixedSize()

                    Text(safety.verdictLabel)
                        .font(.caption.weight(.heavy))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background((safety.isSafeToVisit ? Color.green : Color.red).opacity(0.18))
                        .foregroundStyle(safety.isSafeToVisit ? Color.green : Color.red)
                        .clipShape(RoundedRectangle(cornerRadius: 7))
                        .fixedSize()
                }

                Text(safety.detectedMalware.isEmpty
                     ? "No malware, skimmers, or exploit droppers detected."
                     : "\(safety.detectedMalware.count) Malware Threat(s): " + safety.detectedMalware.map(\.title).joined(separator: " • "))
                    .font(.subheadline)
                    .foregroundStyle(safety.detectedMalware.isEmpty ? Color.secondary : Color.red)
                    .lineLimit(1)

                Spacer(minLength: 6)

                Button("Malware Details") {
                    vm.selectedTab = .malwareScanner
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .fixedSize()
            }
        }
    }

    private func severityCounterCard(title: String, count: Int, severity: SeverityLevel) -> some View {
        Button {
            vm.severityFilter = severity
            vm.selectedTab = .findings
        } label: {
            VStack(spacing: 5) {
                Text("\(count)")
                    .font(.system(size: 25, weight: .bold, design: .rounded))
                    .foregroundStyle(SentinelTheme.severityColor(severity))
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
                Text(title)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.65)
            }
            .frame(minWidth: 40, maxWidth: .infinity)
            .padding(.vertical, 13)
            .padding(.horizontal, 4)
            .background(SentinelTheme.bgCard)
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .stroke(SentinelTheme.severityColor(severity).opacity(count > 0 ? 0.50 : 0.14), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
    }

    private func chartsAndPrioritiesRow(scan: ScanRecord) -> some View {
        HStack(alignment: .top, spacing: 16) {
            SectionCard(
                title: "Top Priority Fixes",
                icon: "wrench.and.screwdriver.fill",
                helpText: "The highest-impact unresolved vulnerabilities found in this scan. Click 'Inspect' to view redacted evidence, code fixes, and AI Analyst guidance."
            ) {
                let topFindings = scan.findings.filter { !$0.isResolved && $0.severity != .informational && $0.status != .incomplete }.prefix(5)
                if topFindings.isEmpty {
                    HStack(spacing: 10) {
                        Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                        Text("All high-priority security checks passed with zero active vulnerabilities.")
                            .font(.subheadline)
                            .foregroundStyle(.green)
                    }
                    .padding(.vertical, 8)
                } else {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(Array(topFindings)) { f in
                            HStack(alignment: .center, spacing: 10) {
                                SeverityBadge(severity: f.severity)
                                    .fixedSize()
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(f.title)
                                        .font(.subheadline.weight(.semibold))
                                        .foregroundStyle(.white)
                                        .lineLimit(1)
                                    Text(f.remediation)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(1)
                                }
                                .layoutPriority(1)
                                Spacer(minLength: 6)
                                Button("Inspect") {
                                    vm.investigate(f)
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                                .fixedSize()
                            }
                            Divider().overlay(SentinelTheme.border)
                        }
                    }
                }
            }
            .frame(minWidth: 425, maxWidth: .infinity)
            .layoutPriority(2)

            SectionCard(
                title: "Score Trend & Severity Distribution",
                icon: "chart.bar.fill",
                helpText: "Visualizes your vulnerability counts by severity level across the current assessment."
            ) {
                let sb = scan.scoreBreakdown
                let items: [(String, Int, Color)] = [
                    ("Critical", sb.criticalCount, SentinelTheme.severityColor(.critical)),
                    ("High", sb.highCount, SentinelTheme.severityColor(.high)),
                    ("Medium", sb.mediumCount, SentinelTheme.severityColor(.medium)),
                    ("Low", sb.lowCount, SentinelTheme.severityColor(.low)),
                    ("Info", sb.infoCount, SentinelTheme.severityColor(.informational))
                ]
                Chart {
                    ForEach(items, id: \.0) { item in
                        BarMark(
                            x: .value("Severity", item.0),
                            y: .value("Count", item.1)
                        )
                        .foregroundStyle(item.2)
                        .cornerRadius(5)
                    }
                }
                .frame(height: 185)
            }
            .frame(minWidth: 240, maxWidth: 410)
            .layoutPriority(0)
        }
    }

    private var emptyStateCard: some View {
        SectionCard(title: "Welcome to Sentinel Website Security Checker", icon: "shield.checkered") {
            VStack(alignment: .leading, spacing: 12) {
                Text("Perform authorized, non-destructive security & malware audits across 11 specialized C++ engines: Malware & Skimmers, SQL/NoSQL/SSTI/XXE/LFI Injections, Reflected & DOM XSS, Cookie Theft & Session Hijacking, Authentication & Credential Attacks, Software/Container Misconfigurations, DDoS Resilience, CMS Plugin Vulnerabilities, and DNS Spoofing Posture.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                HStack(spacing: 12) {
                    Button("Open Scan Setup") {
                        vm.selectedTab = .scanConfig
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(SentinelTheme.accentCyan)

                    Button("Read Step-by-Step Guide") {
                        vm.showStepByStepGuide = true
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
    }
}
