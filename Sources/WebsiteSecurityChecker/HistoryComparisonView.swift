import SwiftUI
import SentinelKit

public struct HistoryComparisonView: View {
    @ObservedObject var vm: AppViewModel

    public init(vm: AppViewModel) {
        self.vm = vm
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 8) {
                            Text("Scan History & Compare")
                                .font(.system(size: 25, weight: .bold))
                                .foregroundStyle(.white)
                            HelpTooltip(
                                "Scan History & Comparison",
                                explanation: "Every assessment is saved automatically in your local SQLite database. Select any two scans below to compare score improvements, fixed vulnerabilities, and newly introduced issues."
                            )
                        }
                        Text("Track security improvements over time and export PDF, HTML, or JSON reports.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        vm.showStepByStepGuide = true
                    } label: {
                        Label("Step-by-Step Guide", systemImage: "book.pages.fill")
                    }
                    .buttonStyle(.bordered)
                }

                comparisonSection

                historyTableSection
            }
            .padding(24)
        }
        .background(SentinelTheme.bgPrimary)
    }

    private var comparisonSection: some View {
        SectionCard(
            title: "Side-by-Side Scan Comparison",
            icon: "arrow.left.and.right.righttriangle.left.righttriangle.right.fill",
            helpText: "Pick an earlier Baseline Scan and a newer Current Scan to see how many points your score improved and which vulnerabilities were resolved."
        ) {
            if vm.scanHistory.count < 2 {
                Text("Run at least two scans to unlock side-by-side comparison and remediation tracking.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(spacing: 20) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Baseline (Earlier) Scan")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                            Picker("Baseline Scan", selection: $vm.comparisonBaselineID) {
                                ForEach(vm.scanHistory) { rec in
                                    Text("\(rec.targetDomain) — \(rec.timestamp.formatted(date: .abbreviated, time: .shortened)) (\(rec.scoreBreakdown.overallScore)/100)")
                                        .tag(UUID?.some(rec.id))
                                }
                            }
                            .labelsHidden()
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Current (Later) Scan")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                            Picker("Current Scan", selection: $vm.comparisonCurrentID) {
                                ForEach(vm.scanHistory) { rec in
                                    Text("\(rec.targetDomain) — \(rec.timestamp.formatted(date: .abbreviated, time: .shortened)) (\(rec.scoreBreakdown.overallScore)/100)")
                                        .tag(UUID?.some(rec.id))
                                }
                            }
                            .labelsHidden()
                        }
                    }

                    if let baseID = vm.comparisonBaselineID,
                       let currID = vm.comparisonCurrentID,
                       let baseScan = vm.scanHistory.first(where: { $0.id == baseID }),
                       let currScan = vm.scanHistory.first(where: { $0.id == currID }) {
                        let diff = SecurityScorer.compareScans(baseline: baseScan, current: currScan)

                        Divider().overlay(SentinelTheme.border)

                        HStack(spacing: 14) {
                            diffStatBox(
                                title: "Score Change",
                                value: diff.scoreDelta >= 0 ? "+\(diff.scoreDelta) pts" : "\(diff.scoreDelta) pts",
                                subtitle: "\(baseScan.scoreBreakdown.overallScore) (\(baseScan.scoreBreakdown.letterGrade)) → \(currScan.scoreBreakdown.overallScore) (\(currScan.scoreBreakdown.letterGrade))",
                                color: diff.scoreDelta >= 0 ? .green : .red
                            )
                            diffStatBox(
                                title: "Resolved",
                                value: "\(diff.resolvedFindings.count)",
                                subtitle: "Fixed since baseline",
                                color: .green
                            )
                            diffStatBox(
                                title: "Newly Introduced",
                                value: "\(diff.newFindings.count)",
                                subtitle: "New since baseline",
                                color: diff.newFindings.isEmpty ? .secondary : .orange
                            )
                            diffStatBox(
                                title: "Remaining Open",
                                value: "\(diff.persistingFindings.count)",
                                subtitle: "Still present",
                                color: .yellow
                            )
                        }
                    }
                }
            }
        }
    }

    private func diffStatBox(title: String, value: String, subtitle: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.title3.bold())
                .foregroundStyle(color)
            Text(subtitle)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(SentinelTheme.bgElevated)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var historyTableSection: some View {
        SectionCard(
            title: "Saved Assessments (\(vm.scanHistory.count))",
            icon: "archivebox.fill",
            helpText: "Click 'Load' on any saved scan to view its dashboard, malware rating, and findings, or click 'Export' to generate a PDF, HTML, or JSON report."
        ) {
            if vm.scanHistory.isEmpty {
                Text("No saved assessments yet.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else {
                VStack(spacing: 8) {
                    ForEach(vm.scanHistory) { record in
                        let safety = SecurityScorer.evaluateVisitorSafety(
                            findings: record.findings,
                            overallScore: record.scoreBreakdown.overallScore
                        )
                        HStack(spacing: 14) {
                            Text(record.scoreBreakdown.letterGrade)
                                .font(.system(size: 15, weight: .bold, design: .rounded))
                                .frame(width: 42, height: 34)
                                .background(SentinelTheme.gradeColor(record.scoreBreakdown.overallScore).opacity(0.2))
                                .foregroundStyle(SentinelTheme.gradeColor(record.scoreBreakdown.overallScore))
                                .clipShape(RoundedRectangle(cornerRadius: 8))

                            VStack(alignment: .leading, spacing: 2) {
                                Text(record.targetURL)
                                    .font(.subheadline.weight(.semibold))
                                    .foregroundStyle(.white)
                                Text("\(record.timestamp.formatted(date: .abbreviated, time: .shortened)) • Security: \(record.scoreBreakdown.overallScore)/100 • Visitor Safety: \(safety.safetyScore)/100 (\(safety.safetyGrade)) • Findings: \(record.findings.count)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }

                            Spacer()

                            Button("Load") {
                                vm.activeScan = record
                                vm.selectedFinding = record.findings.first
                                vm.selectedTab = .dashboard
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)

                            Menu {
                                ForEach(ReportFormat.allCases, id: \.rawValue) { fmt in
                                    Button("Export \(fmt.rawValue)") {
                                        vm.exportReport(for: record, format: fmt)
                                    }
                                }
                            } label: {
                                Label("Export", systemImage: "square.and.arrow.up")
                            }
                            .controlSize(.small)

                            Button(role: .destructive) {
                                vm.db.deleteScan(id: record.id)
                                vm.reloadPersistence()
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                            .foregroundStyle(.red)
                        }
                        .padding(10)
                        .background(SentinelTheme.bgElevated)
                        .clipShape(RoundedRectangle(cornerRadius: 9))
                    }
                }
            }
        }
    }
}
