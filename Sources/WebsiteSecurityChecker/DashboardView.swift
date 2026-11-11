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
            VStack(alignment: .leading, spacing: 20) {
                headerBar

                if vm.isScanning {
                    liveScanBanner
                }

                if let scan = vm.activeScan {
                    scoreAndSeverityRow(scan: scan)
                    chartsRow(scan: scan)
                    recommendationsAndFactorsRow(scan: scan)
                } else {
                    emptyStateCard
                }

                recentScansSection
            }
            .padding(24)
        }
        .background(SentinelTheme.bgPrimary)
    }

    private var headerBar: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Security Posture Dashboard")
                    .font(.system(size: 26, weight: .bold))
                    .foregroundStyle(.white)
                if let scan = vm.activeScan {
                    Text("Target: \(scan.targetURL) • Assessed \(scan.timestamp.formatted(date: .abbreviated, time: .shortened))")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                } else {
                    Text("Configure an authorized target domain to begin a comprehensive security audit.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
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
                Label("New Security Scan", systemImage: "play.fill")
            }
            .buttonStyle(.borderedProminent)
            .tint(SentinelTheme.accentCyan)
        }
    }

    private var liveScanBanner: some View {
        SectionCard(title: "Active Security Scan in Progress", icon: "waveform.path.ecg") {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Current Module: \(vm.liveProgress.currentModule)")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.white)
                    Spacer()
                    Text("Coverage: \(Int(vm.liveProgress.coveragePercent))% • Endpoints: \(vm.liveProgress.endpointsExamined) • Findings: \(vm.liveProgress.findingsCount)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                ProgressView(value: vm.liveProgress.coveragePercent, total: 100.0)
                    .tint(SentinelTheme.accentCyan)
                HStack(spacing: 12) {
                    Button(vm.isPaused ? "Resume Scan" : "Pause Scan") {
                        vm.togglePauseScan()
                    }
                    .buttonStyle(.bordered)

                    Button(role: .destructive) {
                        vm.emergencyStopScan()
                    } label: {
                        Label("Emergency Stop", systemImage: "xmark.octagon.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                }
            }
        }
    }

    private func scoreAndSeverityRow(scan: ScanRecord) -> some View {
        let sb = scan.scoreBreakdown
        return HStack(alignment: .top, spacing: 16) {
            // Score & Grade Card — Fixed minimum width & highest layout priority so it NEVER shrinks into unreadability
            SectionCard(title: "Overall Security Score", icon: "gauge.with.dots.needle.67percent") {
                HStack(spacing: 20) {
                    ZStack {
                        Circle()
                            .stroke(Color.white.opacity(0.08), lineWidth: 12)
                            .frame(width: 110, height: 110)
                        Circle()
                            .trim(from: 0, to: CGFloat(sb.overallScore) / 100.0)
                            .stroke(
                                SentinelTheme.gradeColor(sb.overallScore),
                                style: StrokeStyle(lineWidth: 12, lineCap: .round)
                            )
                            .rotationEffect(.degrees(-90))
                            .frame(width: 110, height: 110)
                        VStack(spacing: 2) {
                            Text("\(sb.overallScore)")
                                .font(.system(size: 32, weight: .heavy, design: .rounded))
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
                                .font(.system(size: 22, weight: .bold, design: .rounded))
                                .lineLimit(1)
                                .fixedSize(horizontal: true, vertical: false)
                                .padding(.horizontal, 12)
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
                            HStack {
                                Text("Scan Coverage:")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: true, vertical: false)
                                Text(String(format: "%.0f%%", sb.coveragePercent))
                                    .font(.caption.bold())
                                    .foregroundStyle(sb.coveragePercent == 100 ? .green : .orange)
                                    .fixedSize(horizontal: true, vertical: false)
                            }
                            ProgressView(value: sb.coveragePercent, total: 100.0)
                                .tint(sb.coveragePercent == 100 ? .green : .orange)
                        }

                        Text("Verified: \(sb.verifiedCount) • Suspected: \(sb.suspectedCount) • Root Causes: \(sb.deduplicatedRootCauses)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .fixedSize(horizontal: true, vertical: false)
                    }
                }
            }
            .frame(minWidth: 425, idealWidth: 435, maxWidth: 450)
            .layoutPriority(2)

            // Severity Breakdown Cards & Metadata Box — Shrinks flexibly when window narrows
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

                        VStack(alignment: .leading, spacing: 4) {
                            Label("Endpoints: \(scan.endpointsExamined) • Status: \(scan.status) • Duration: \(scan.durationSeconds)s", systemImage: "network")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .minimumScaleFactor(0.8)
                        }
                    }
                }
            }
            .frame(minWidth: 240, maxWidth: .infinity)
            .layoutPriority(0)
        }
    }

    private func severityCounterCard(title: String, count: Int, severity: SeverityLevel) -> some View {
        Button {
            vm.severityFilter = severity
            vm.selectedTab = .findings
        } label: {
            VStack(spacing: 6) {
                Text("\(count)")
                    .font(.system(size: 26, weight: .bold, design: .rounded))
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
            .padding(.vertical, 14)
            .padding(.horizontal, 4)
            .background(SentinelTheme.bgCard)
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .stroke(SentinelTheme.severityColor(severity).opacity(count > 0 ? 0.55 : 0.15), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
    }

    private func chartsRow(scan: ScanRecord) -> some View {
        HStack(alignment: .top, spacing: 16) {
            SectionCard(title: "Findings by Severity", icon: "chart.bar.fill") {
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
                .frame(height: 170)
            }

            SectionCard(title: "Historical Security Score Trend", icon: "chart.xyaxis.line") {
                let historyReversed = Array(vm.scanHistory.prefix(12).reversed())
                if historyReversed.isEmpty {
                    Text("Run multiple assessments to track security score trends over time.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .frame(height: 170)
                } else {
                    Chart {
                        ForEach(Array(historyReversed.enumerated()), id: \.element.id) { idx, rec in
                            LineMark(
                                x: .value("Scan", "#\(idx + 1)"),
                                y: .value("Score", rec.scoreBreakdown.overallScore)
                            )
                            .foregroundStyle(SentinelTheme.accentCyan)
                            .symbol(Circle())

                            PointMark(
                                x: .value("Scan", "#\(idx + 1)"),
                                y: .value("Score", rec.scoreBreakdown.overallScore)
                            )
                            .foregroundStyle(SentinelTheme.gradeColor(rec.scoreBreakdown.overallScore))
                        }
                    }
                    .chartYScale(domain: 0...100)
                    .frame(height: 170)
                }
            }
        }
    }

    private func recommendationsAndFactorsRow(scan: ScanRecord) -> some View {
        HStack(alignment: .top, spacing: 16) {
            SectionCard(title: "Top Priority Security Remediations", icon: "wrench.and.screwdriver.fill") {
                let topFindings = scan.findings.filter { !$0.isResolved && $0.severity != .informational && $0.status != .incomplete }.prefix(4)
                if topFindings.isEmpty {
                    Text("No active high-priority vulnerabilities remaining in this assessment.")
                        .font(.subheadline)
                        .foregroundStyle(.green)
                } else {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(Array(topFindings)) { f in
                            HStack(alignment: .top, spacing: 10) {
                                SeverityBadge(severity: f.severity)
                                    .fixedSize()
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(f.title)
                                        .font(.subheadline.weight(.semibold))
                                        .foregroundStyle(.white)
                                    Text(f.remediation)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(2)
                                }
                                .layoutPriority(1)
                                Spacer(minLength: 6)
                                Button("Investigate") {
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

            SectionCard(title: "Scoring Factors & Methodology", icon: "function") {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(scan.scoreBreakdown.scoringFactors, id: \.self) { factor in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(SentinelTheme.accentCyan)
                                .font(.caption)
                            Text(factor)
                                .font(.caption)
                                .foregroundStyle(.white.opacity(0.9))
                        }
                    }
                    Divider().overlay(SentinelTheme.border)
                    Text(scan.scoreBreakdown.algorithmExplanation)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(minWidth: 240, maxWidth: 420)
            .layoutPriority(0)
        }
    }

    private var emptyStateCard: some View {
        SectionCard(title: "Welcome to Website Security Checker", icon: "shield.checkered") {
            VStack(alignment: .leading, spacing: 10) {
                Text("Start an authorized security audit to evaluate SQL Injection indicators, Reflected & DOM XSS, Authentication & Session Cookies, CSRF protections, Server-Side Misconfigurations, Security Headers, TLS/HTTPS, API Security, Information Disclosure, and OWASP Top 10 coverage.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Button("Configure First Security Assessment") {
                    vm.selectedTab = .scanConfig
                }
                .buttonStyle(.borderedProminent)
                .tint(SentinelTheme.accentCyan)
            }
        }
    }

    private var recentScansSection: some View {
        SectionCard(title: "Recent Security Assessments", icon: "clock.fill") {
            if vm.scanHistory.isEmpty {
                Text("No scan history recorded yet.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                VStack(spacing: 8) {
                    ForEach(vm.scanHistory.prefix(6)) { record in
                        HStack {
                            Text(record.scoreBreakdown.letterGrade)
                                .font(.system(size: 14, weight: .bold, design: .rounded))
                                .frame(width: 36, height: 28)
                                .background(SentinelTheme.gradeColor(record.scoreBreakdown.overallScore).opacity(0.2))
                                .foregroundStyle(SentinelTheme.gradeColor(record.scoreBreakdown.overallScore))
                                .clipShape(RoundedRectangle(cornerRadius: 6))

                            VStack(alignment: .leading, spacing: 2) {
                                Text(record.targetURL)
                                    .font(.subheadline.weight(.medium))
                                    .foregroundStyle(.white)
                                Text("\(record.timestamp.formatted(date: .abbreviated, time: .shortened)) • Score: \(record.scoreBreakdown.overallScore)/100 • Coverage: \(Int(record.scoreBreakdown.coveragePercent))% • Findings: \(record.findings.count)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("View") {
                                vm.activeScan = record
                                vm.selectedFinding = record.findings.first
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        }
                        .padding(8)
                        .background(vm.activeScan?.id == record.id ? SentinelTheme.bgElevated : Color.clear)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                }
            }
        }
    }
}
