import SwiftUI
import SentinelKit

public struct FindingsView: View {
    @ObservedObject var vm: AppViewModel
    @State private var showEvidence = true
    @State private var showExplanation = true
    @State private var showReproduction = true
    @State private var showRemediation = true

    public init(vm: AppViewModel) {
        self.vm = vm
    }

    public var body: some View {
        VStack(spacing: 0) {
            filterToolbar
                .padding(16)
                .background(SentinelTheme.bgCard)

            Divider().overlay(SentinelTheme.border)

            HSplitView {
                findingsListPane
                    .frame(minWidth: 340, idealWidth: 400, maxWidth: 480)

                findingDetailPane
                    .frame(minWidth: 460, maxWidth: .infinity)
            }
        }
        .background(SentinelTheme.bgPrimary)
    }

    private var filterToolbar: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField("Search title, URL, parameter, or OWASP category...", text: $vm.searchQuery)
                        .textFieldStyle(.plain)
                }
                .padding(7)
                .background(SentinelTheme.bgElevated)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .frame(maxWidth: 320)

                Picker("Severity", selection: $vm.severityFilter) {
                    Text("All Severities").tag(SeverityLevel?.none)
                    ForEach(SeverityLevel.allCases, id: \.self) { sev in
                        Text(sev.rawValue).tag(SeverityLevel?.some(sev))
                    }
                }
                .frame(width: 160)

                Picker("Category", selection: $vm.categoryFilter) {
                    Text("All Categories").tag("All")
                    ForEach(ScanCategory.allCases) { cat in
                        Text(cat.rawValue).tag(cat.rawValue)
                    }
                }
                .frame(width: 210)

                Picker("Status", selection: $vm.statusFilter) {
                    Text("All Statuses").tag(FindingStatus?.none)
                    ForEach(FindingStatus.allCases, id: \.self) { st in
                        Text(st.displayLabel).tag(FindingStatus?.some(st))
                    }
                }
                .frame(width: 175)

                Toggle("Sort by Confidence", isOn: $vm.sortByConfidence)
                    .toggleStyle(.checkbox)
                    .font(.caption)

                Toggle("Hide Resolved", isOn: $vm.hideResolved)
                    .toggleStyle(.checkbox)
                    .font(.caption)

                Spacer()
            }
        }
    }

    private var findingsListPane: some View {
        let items = vm.filteredFindings
        return VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Discovered Findings (\(items.count))")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.secondary)
                Spacer()
                if vm.severityFilter != nil || vm.categoryFilter != "All" || vm.statusFilter != nil || !vm.searchQuery.isEmpty {
                    Button("Reset Filters") {
                        vm.severityFilter = nil
                        vm.categoryFilter = "All"
                        vm.statusFilter = nil
                        vm.searchQuery = ""
                    }
                    .buttonStyle(.link)
                    .font(.caption)
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)

            Divider().overlay(SentinelTheme.border)

            if items.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 34))
                        .foregroundStyle(.secondary)
                    Text("No findings match the current filter criteria.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(items) { finding in
                            findingRowButton(for: finding)
                        }
                    }
                    .padding(12)
                }
            }
        }
        .background(SentinelTheme.bgPrimary)
    }

    private func findingRowButton(for finding: VulnerabilityFinding) -> some View {
        let isSelected = (vm.selectedFinding?.id == finding.id)
        let bg = isSelected ? SentinelTheme.bgElevated : SentinelTheme.bgCard
        let strokeColor = isSelected ? SentinelTheme.accentCyan.opacity(0.7) : SentinelTheme.border

        return Button {
            vm.selectedFinding = finding
        } label: {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    SeverityBadge(severity: finding.severity)
                    StatusBadge(status: finding.status)
                    Spacer()
                    if finding.isResolved {
                        Text("RESOLVED")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundStyle(.green)
                    } else {
                        Text(String(format: "CVSS %.1f", finding.cvssScore))
                            .font(.caption2.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }
                Text(finding.title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(finding.isResolved ? Color.secondary : Color.white)
                    .multilineTextAlignment(.leading)
                Text(finding.affectedURL)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(bg)
            .overlay(
                RoundedRectangle(cornerRadius: 9)
                    .stroke(strokeColor, lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: 9))
        }
        .buttonStyle(.plain)
    }

    private var findingDetailPane: some View {
        ScrollView {
            if let f = vm.selectedFinding {
                VStack(alignment: .leading, spacing: 18) {
                    // Header Card
                    SectionCard {
                        VStack(alignment: .leading, spacing: 12) {
                            HStack(spacing: 10) {
                                SeverityBadge(severity: f.severity)
                                StatusBadge(status: f.status)
                                Text("Confidence: \(f.confidence.rawValue)")
                                    .font(.caption.weight(.semibold))
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 3)
                                    .background(SentinelTheme.bgElevated)
                                    .clipShape(RoundedRectangle(cornerRadius: 5))
                                Text(String(format: "CVSS: %.1f", f.cvssScore))
                                    .font(.caption.weight(.semibold))
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 3)
                                    .background(SentinelTheme.bgElevated)
                                    .clipShape(RoundedRectangle(cornerRadius: 5))
                                Spacer()
                                Button {
                                    vm.toggleResolved(for: f)
                                } label: {
                                    Label(f.isResolved ? "Mark as Unresolved" : "Mark as Resolved",
                                          systemImage: f.isResolved ? "arrow.uturn.backward.circle" : "checkmark.circle.fill")
                                }
                                .buttonStyle(.bordered)
                                .tint(f.isResolved ? .orange : .green)

                                Button {
                                    vm.investigate(f)
                                } label: {
                                    Label("Investigate with AI Analyst", systemImage: "brain.head.profile")
                                }
                                .buttonStyle(.borderedProminent)
                                .tint(SentinelTheme.accentCyan)
                            }

                            Text(f.title)
                                .font(.title2.bold())
                                .foregroundStyle(.white)

                            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                                GridRow {
                                    Text("Affected URL:")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.secondary)
                                    Text(f.affectedURL)
                                        .font(.caption.monospaced())
                                        .foregroundStyle(SentinelTheme.accentCyan)
                                        .textSelection(.enabled)
                                }
                                GridRow {
                                    Text("Affected Component:")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.secondary)
                                    Text(f.affectedParameter)
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.white)
                                        .textSelection(.enabled)
                                }
                                GridRow {
                                    Text("Category & OWASP:")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.secondary)
                                    Text("\(f.category) • \(f.owaspCategory)")
                                        .font(.caption)
                                        .foregroundStyle(.white)
                                }
                            }
                        }
                    }

                    // Expandable Section 1: Supporting Technical Evidence
                    SectionCard {
                        DisclosureGroup("Supporting Technical Evidence (Sensitive Data Redacted)", isExpanded: $showEvidence) {
                            Text(f.evidence)
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundStyle(Color(red: 0.65, green: 0.85, blue: 1.0))
                                .padding(12)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.black.opacity(0.45))
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                                .padding(.top, 8)
                                .textSelection(.enabled)
                        }
                        .font(.headline)
                        .foregroundStyle(.white)
                    }

                    // Expandable Section 2: Technical Explanation & Security Impact
                    SectionCard {
                        DisclosureGroup("Technical Explanation & Security Impact", isExpanded: $showExplanation) {
                            VStack(alignment: .leading, spacing: 10) {
                                Text("Why Sentinel Flagged This:")
                                    .font(.caption.weight(.bold))
                                    .foregroundStyle(.secondary)
                                Text(f.technicalExplanation)
                                    .font(.subheadline)
                                    .foregroundStyle(.white.opacity(0.92))

                                Divider().overlay(SentinelTheme.border)

                                Text("Potential Security Impact:")
                                    .font(.caption.weight(.bold))
                                    .foregroundStyle(.secondary)
                                Text(f.impact)
                                    .font(.subheadline)
                                    .foregroundStyle(.white.opacity(0.92))
                            }
                            .padding(.top, 8)
                        }
                        .font(.headline)
                        .foregroundStyle(.white)
                    }

                    // Expandable Section 3: Safe Reproduction Instructions
                    SectionCard {
                        DisclosureGroup("Safe Reproduction & Validation Instructions", isExpanded: $showReproduction) {
                            Text(f.safeReproduction)
                                .font(.subheadline)
                                .foregroundStyle(.white.opacity(0.92))
                                .padding(.top, 8)
                                .textSelection(.enabled)
                        }
                        .font(.headline)
                        .foregroundStyle(.white)
                    }

                    // Expandable Section 4: Recommended Remediation
                    SectionCard {
                        DisclosureGroup("Recommended Remediation & Fix", isExpanded: $showRemediation) {
                            Text(f.remediation)
                                .font(.subheadline)
                                .foregroundStyle(.green.opacity(0.92))
                                .padding(.top, 8)
                                .textSelection(.enabled)
                        }
                        .font(.headline)
                        .foregroundStyle(.white)
                    }
                }
                .padding(20)
            } else {
                VStack(spacing: 12) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.system(size: 40))
                        .foregroundStyle(.secondary)
                    Text("Select a finding from the list to inspect its technical evidence, impact, and remediation.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding(40)
            }
        }
    }
}
