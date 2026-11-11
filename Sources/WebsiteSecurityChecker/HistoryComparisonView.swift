import SwiftUI
import SentinelKit

public struct HistoryComparisonView: View {
    @ObservedObject var vm: AppViewModel

    public init(vm: AppViewModel) {
        self.vm = vm
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Scan History & Remediation Comparison")
                    .font(.system(size: 26, weight: .bold))
                    .foregroundStyle(.white)

                comparisonSection

                historyTableSection
            }
            .padding(24)
        }
        .background(SentinelTheme.bgPrimary)
    }

    private var comparisonSection: some View {
        SectionCard(title: "Compare Two Assessments (Remediation Tracking)", icon: "arrow.left.and.right.righttriangle.left.righttriangle.right.fill") {
            if vm.scanHistory.count < 2 {
                Text("Run at least two security assessments to compare score changes, newly discovered vulnerabilities, and resolved vulnerabilities.")
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

                        HStack(spacing: 16) {
                            diffStatBox(
                                title: "Score Delta",
                                value: diff.scoreDelta >= 0 ? "+\(diff.scoreDelta) pts" : "\(diff.scoreDelta) pts",
                                subtitle: "\(baseScan.scoreBreakdown.overallScore) (\(baseScan.scoreBreakdown.letterGrade)) → \(currScan.scoreBreakdown.overallScore) (\(currScan.scoreBreakdown.letterGrade))",
                                color: diff.scoreDelta >= 0 ? .green : .red
                            )
                            diffStatBox(
                                title: "Resolved Vulnerabilities",
                                value: "\(diff.resolvedFindings.count)",
                                subtitle: "Fixed since baseline",
                                color: .green
                            )
                            diffStatBox(
                                title: "Newly Discovered",
                                value: "\(diff.newFindings.count)",
                                subtitle: "Introduced since baseline",
                                color: diff.newFindings.isEmpty ? .secondary : .orange
                            )
                            diffStatBox(
                                title: "Remaining Open",
                                value: "\(diff.persistingFindings.count)",
                                subtitle: "Present in both scans",
                                color: .yellow
                            )
                        }

                        if !diff.resolvedFindings.isEmpty {
                            Text("Resolved Since Baseline (\(diff.resolvedFindings.count))")
                                .font(.caption.weight(.bold))
                                .foregroundStyle(.green)
                            ForEach(diff.resolvedFindings.prefix(5)) { f in
                                HStack {
                                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                                    Text(f.title).font(.caption.weight(.medium)).foregroundStyle(.white)
                                    Spacer()
                                    Text(f.affectedURL).font(.caption2).foregroundStyle(.secondary)
                                }
                            }
                        }

                        if !diff.newFindings.isEmpty {
                            Text("Newly Discovered in Current Scan (\(diff.newFindings.count))")
                                .font(.caption.weight(.bold))
                                .foregroundStyle(.orange)
                            ForEach(diff.newFindings.prefix(5)) { f in
                                HStack {
                                    SeverityBadge(severity: f.severity)
                                    Text(f.title).font(.caption.weight(.medium)).foregroundStyle(.white)
                                    Spacer()
                                    Text(f.affectedURL).font(.caption2).foregroundStyle(.secondary)
                                }
                            }
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
                .font(.title2.bold())
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
        SectionCard(title: "All Saved Security Assessments (\(vm.scanHistory.count))", icon: "archivebox.fill") {
            if vm.scanHistory.isEmpty {
                Text("No saved assessments yet. Run a scan to populate persistent scan history.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else {
                VStack(spacing: 10) {
                    ForEach(vm.scanHistory) { record in
                        HStack(spacing: 14) {
                            Text(record.scoreBreakdown.letterGrade)
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .frame(width: 44, height: 36)
                                .background(SentinelTheme.gradeColor(record.scoreBreakdown.overallScore).opacity(0.2))
                                .foregroundStyle(SentinelTheme.gradeColor(record.scoreBreakdown.overallScore))
                                .clipShape(RoundedRectangle(cornerRadius: 8))

                            VStack(alignment: .leading, spacing: 3) {
                                Text(record.targetURL)
                                    .font(.subheadline.weight(.semibold))
                                    .foregroundStyle(.white)
                                Text("\(record.timestamp.formatted(date: .abbreviated, time: .standard)) • Score: \(record.scoreBreakdown.overallScore)/100 • Coverage: \(Int(record.scoreBreakdown.coveragePercent))% • Findings: \(record.findings.count) (Critical: \(record.scoreBreakdown.criticalCount), High: \(record.scoreBreakdown.highCount))")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }

                            Spacer()

                            Button("Load Assessment") {
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
                        .padding(12)
                        .background(SentinelTheme.bgElevated)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                }
            }
        }
    }
}
