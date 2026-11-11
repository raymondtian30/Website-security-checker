import SwiftUI
import SentinelKit

public struct FindingsView: View {
    @ObservedObject var vm: AppViewModel

    public init(vm: AppViewModel) {
        self.vm = vm
    }

    public var body: some View {
        VStack(spacing: 0) {
            filterToolbar
                .padding(14)
                .background(SentinelTheme.bgCard)

            Divider().overlay(SentinelTheme.border)

            HSplitView {
                findingsListPane
                    .frame(minWidth: 320, idealWidth: 370, maxWidth: 440)

                findingDetailInspector
                    .frame(minWidth: 480, maxWidth: .infinity)
            }
        }
        .background(SentinelTheme.bgPrimary)
    }

    private var filterToolbar: some View {
        HStack(spacing: 12) {
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Search findings, URLs, parameters, or OWASP...", text: $vm.searchQuery)
                    .textFieldStyle(.plain)
            }
            .padding(7)
            .background(SentinelTheme.bgElevated)
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .frame(maxWidth: 280)

            Picker("Severity", selection: $vm.severityFilter) {
                Text("All Severities").tag(SeverityLevel?.none)
                ForEach(SeverityLevel.allCases, id: \.self) { sev in
                    Text(sev.rawValue).tag(SeverityLevel?.some(sev))
                }
            }
            .labelsHidden()
            .frame(width: 135)

            Picker("Category", selection: $vm.categoryFilter) {
                Text("All Categories").tag("All")
                ForEach(ScanCategory.allCases) { cat in
                    Text(cat.rawValue).tag(cat.rawValue)
                }
            }
            .labelsHidden()
            .frame(width: 185)

            Picker("Status", selection: $vm.statusFilter) {
                Text("All Statuses").tag(FindingStatus?.none)
                ForEach(FindingStatus.allCases, id: \.self) { st in
                    Text(st.displayLabel).tag(FindingStatus?.some(st))
                }
            }
            .labelsHidden()
            .frame(width: 150)

            Toggle("Hide Resolved", isOn: $vm.hideResolved)
                .toggleStyle(.checkbox)
                .font(.caption)

            HelpTooltip(
                "Filtering & Sorting Findings",
                explanation: "Filter findings by Severity, Scanner Category, or Verification Status (Verified vs Suspected). Mark items as Resolved as you fix them to see your updated score."
            )

            Spacer()
        }
    }

    private var findingsListPane: some View {
        let items = vm.filteredFindings
        return VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Findings (\(items.count))")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.secondary)
                Spacer()
                if vm.severityFilter != nil || vm.categoryFilter != "All" || vm.statusFilter != nil || !vm.searchQuery.isEmpty {
                    Button("Clear Filters") {
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
            .padding(.vertical, 9)

            Divider().overlay(SentinelTheme.border)

            if items.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 32))
                        .foregroundStyle(.secondary)
                    Text("No findings match the current filter.")
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
            VStack(alignment: .leading, spacing: 5) {
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
            .padding(11)
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

    private var findingDetailInspector: some View {
        ScrollView {
            if let f = vm.selectedFinding {
                let analysis = f.aiAnalysis ?? AISecurityAnalyst.generateDeterministicAnalysis(
                    for: f,
                    allFindings: vm.activeScan?.findings ?? [f]
                )

                VStack(alignment: .leading, spacing: 16) {
                    // Unified Header Card
                    SectionCard {
                        VStack(alignment: .leading, spacing: 12) {
                            HStack(spacing: 10) {
                                SeverityBadge(severity: f.severity)
                                StatusBadge(status: f.status)
                                HStack(spacing: 4) {
                                    Text("Confidence: \(f.confidence.rawValue) • CVSS: \(String(format: "%.1f", f.cvssScore))")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.secondary)
                                    HelpTooltip(
                                        "Verification, Confidence & CVSS",
                                        explanation: "• Verified: Deterministic proof captured in HTTP response.\n• Suspected: Behavioral anomaly requiring review.\n• CVSS (0–10): Industry-standard severity score."
                                    )
                                }
                                Spacer()
                                Button {
                                    vm.toggleResolved(for: f)
                                } label: {
                                    Label(f.isResolved ? "Mark Unresolved" : "Mark Resolved",
                                          systemImage: f.isResolved ? "arrow.uturn.backward.circle" : "checkmark.circle.fill")
                                }
                                .buttonStyle(.bordered)
                                .tint(f.isResolved ? .orange : .green)
                                .controlSize(.small)
                            }

                            Text(f.title)
                                .font(.title3.bold())
                                .foregroundStyle(.white)

                            HStack(spacing: 16) {
                                Label(f.affectedURL, systemImage: "link")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(SentinelTheme.accentCyan)
                                    .lineLimit(1)
                                    .textSelection(.enabled)
                                Label(f.affectedParameter, systemImage: "tag.fill")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.white.opacity(0.85))
                                    .lineLimit(1)
                                    .textSelection(.enabled)
                                Label(f.owaspCategory, systemImage: "shield.lefthalf.filled")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }

                            Picker("Inspector View", selection: $vm.inspectorTab) {
                                Text("1. Overview & Fix").tag(0)
                                Text("2. Technical Evidence & Reproduction").tag(1)
                                Text("3. AI Security Analyst Walkthrough").tag(2)
                            }
                            .labelsHidden()
                            .pickerStyle(.segmented)
                        }
                    }

                    if vm.inspectorTab == 0 {
                        SectionCard(title: "Why Sentinel Flagged This & Security Impact", icon: "exclamationmark.shield.fill") {
                            VStack(alignment: .leading, spacing: 10) {
                                Text(f.technicalExplanation)
                                    .font(.subheadline)
                                    .foregroundStyle(.white.opacity(0.92))
                                Divider().overlay(SentinelTheme.border)
                                Text("Security Impact: \(f.impact)")
                                    .font(.subheadline)
                                    .foregroundStyle(.orange.opacity(0.95))
                            }
                        }

                        SectionCard(title: "Recommended Fix & Secure Code Pattern", icon: "wrench.and.screwdriver.fill") {
                            VStack(alignment: .leading, spacing: 10) {
                                Text(f.remediation)
                                    .font(.subheadline)
                                    .foregroundStyle(.green.opacity(0.95))
                                    .textSelection(.enabled)

                                Text(analysis.secureCodePattern)
                                    .font(.system(size: 12, design: .monospaced))
                                    .foregroundStyle(Color.green.opacity(0.9))
                                    .padding(12)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(Color.black.opacity(0.45))
                                    .clipShape(RoundedRectangle(cornerRadius: 8))
                                    .textSelection(.enabled)
                            }
                        }
                    } else if vm.inspectorTab == 1 {
                        SectionCard(
                            title: "Supporting Technical Evidence (Redacted)",
                            icon: "terminal.fill",
                            helpText: "Actual HTTP headers or response snippets captured by the C++ engine. Passwords, API keys, and session tokens are automatically replaced with [REDACTED]."
                        ) {
                            Text(f.evidence)
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundStyle(Color(red: 0.65, green: 0.85, blue: 1.0))
                                .padding(12)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.black.opacity(0.45))
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                                .textSelection(.enabled)
                        }

                        SectionCard(title: "Safe Validation & Reproduction Steps", icon: "checkmark.gobackward") {
                            Text(f.safeReproduction)
                                .font(.subheadline)
                                .foregroundStyle(.white.opacity(0.92))
                                .textSelection(.enabled)
                        }
                    } else {
                        SectionCard(
                            title: "AI Security Analyst Walkthrough",
                            icon: "brain.head.profile",
                            helpText: "Works offline using Sentinel's deterministic correlation engine, or queries your configured OpenAI/Anthropic/Gemini model stored in macOS Keychain."
                        ) {
                            VStack(alignment: .leading, spacing: 12) {
                                HStack {
                                    Text("Priority: \(analysis.remediationPriority)")
                                        .font(.caption.weight(.bold))
                                        .foregroundStyle(SentinelTheme.accentCyan)
                                    Spacer()
                                    Button {
                                        vm.runEnhancedAIAnalysis()
                                    } label: {
                                        Label(
                                            vm.hasSavedAPIKey ? "Run Cloud LLM Analysis (\(vm.selectedAIProvider.rawValue))" : "Refresh Local Analyst",
                                            systemImage: "sparkles"
                                        )
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .tint(SentinelTheme.accentCyan)
                                    .controlSize(.small)
                                    .disabled(vm.isRequestingAI)
                                }

                                Text(analysis.plainLanguageSummary)
                                    .font(.subheadline)
                                    .foregroundStyle(.white.opacity(0.92))

                                Divider().overlay(SentinelTheme.border)

                                Text("Correlated Risks in This Scan:")
                                    .font(.caption.weight(.bold))
                                    .foregroundStyle(.secondary)
                                Text(analysis.relatedFindingsAnalysis)
                                    .font(.subheadline)
                                    .foregroundStyle(.white.opacity(0.9))

                                Divider().overlay(SentinelTheme.border)

                                Text("False-Positive Assessment:")
                                    .font(.caption.weight(.bold))
                                    .foregroundStyle(.secondary)
                                Text(analysis.falsePositiveAssessment)
                                    .font(.subheadline)
                                    .foregroundStyle(.white.opacity(0.9))

                                Divider().overlay(SentinelTheme.border)

                                Text("Controlled Verification Guide:")
                                    .font(.caption.weight(.bold))
                                    .foregroundStyle(.secondary)
                                Text(analysis.controlledValidationProcedure)
                                    .font(.subheadline)
                                    .foregroundStyle(.white.opacity(0.9))
                            }
                        }
                    }
                }
                .padding(20)
            } else {
                VStack(spacing: 12) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.system(size: 38))
                        .foregroundStyle(.secondary)
                    Text("Select a finding on the left to inspect its overview, redacted evidence, and AI Analyst walkthrough.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }
}
