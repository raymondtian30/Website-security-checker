import SwiftUI
import SentinelKit

public struct InvestigationView: View {
    @ObservedObject var vm: AppViewModel

    public init(vm: AppViewModel) {
        self.vm = vm
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                headerRow

                if let finding = vm.selectedFinding {
                    let analysis = finding.aiAnalysis ?? AISecurityAnalyst.generateDeterministicAnalysis(
                        for: finding,
                        allFindings: vm.activeScan?.findings ?? [finding]
                    )

                    summaryCard(finding: finding, analysis: analysis)
                    evidenceAndVerificationRow(finding: finding, analysis: analysis)
                    abuseAndCorrelationRow(finding: finding, analysis: analysis)
                    validationAndRemediationCard(finding: finding, analysis: analysis)
                } else {
                    SectionCard(title: "No Finding Selected for Investigation", icon: "magnifyingglass.circle") {
                        Text("Select any vulnerability finding from the Dashboard or Findings tab to launch an interactive AI Security Analyst walkthrough.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .padding(24)
        }
        .background(SentinelTheme.bgPrimary)
    }

    private var headerRow: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Security Investigation & AI Analyst Workbench")
                    .font(.system(size: 26, weight: .bold))
                    .foregroundStyle(.white)
                Text("Step-by-step discovery walkthrough, false-positive assessment, compound risk correlation, and controlled validation guide.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if vm.selectedFinding != nil {
                Button {
                    vm.runEnhancedAIAnalysis()
                } label: {
                    if vm.isRequestingAI {
                        ProgressView().controlSize(.small)
                    } else {
                        Label(
                            vm.hasSavedAPIKey ? "Run Enhanced Cloud AI Analysis (\(vm.selectedAIProvider.rawValue))" : "Refresh Local AI Analyst",
                            systemImage: "sparkles"
                        )
                    }
                }
                .buttonStyle(.borderedProminent)
                .tint(SentinelTheme.accentCyan)
                .disabled(vm.isRequestingAI)
            }
        }
    }

    private func summaryCard(finding: VulnerabilityFinding, analysis: AIAnalysisResult) -> some View {
        SectionCard(title: "1. What Was Discovered & Why Sentinel Flagged It", icon: "sparkle.magnifyingglass") {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    SeverityBadge(severity: finding.severity)
                    StatusBadge(status: finding.status)
                    Text("Confidence: \(finding.confidence.rawValue)")
                        .font(.caption.weight(.semibold))
                    Text("Priority: \(analysis.remediationPriority)")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(SentinelTheme.accentCyan)
                    Spacer()
                    Text("Analyst Engine: \(analysis.generatedByModel)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }

                Text(finding.title)
                    .font(.title3.bold())
                    .foregroundStyle(.white)

                Text(analysis.plainLanguageSummary)
                    .font(.subheadline)
                    .foregroundStyle(.white.opacity(0.92))
                    .textSelection(.enabled)
            }
        }
    }

    private func evidenceAndVerificationRow(finding: VulnerabilityFinding, analysis: AIAnalysisResult) -> some View {
        HStack(alignment: .top, spacing: 16) {
            SectionCard(title: "2. Supporting Scanner Evidence (Redacted)", icon: "terminal.fill") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Endpoint: \(finding.affectedURL) • Parameter/Component: \(finding.affectedParameter)")
                        .font(.caption.monospaced())
                        .foregroundStyle(SentinelTheme.accentCyan)
                    Text(finding.evidence)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Color(red: 0.65, green: 0.85, blue: 1.0))
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.black.opacity(0.45))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                        .textSelection(.enabled)
                }
            }

            SectionCard(title: "3. Verification Status & False-Positive Assessment", icon: "checkmark.shield.fill") {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text("Classification:")
                            .font(.caption.weight(.bold))
                            .foregroundStyle(.secondary)
                        StatusBadge(status: finding.status)
                    }
                    Text(analysis.falsePositiveAssessment)
                        .font(.subheadline)
                        .foregroundStyle(.white.opacity(0.9))
                    Divider().overlay(SentinelTheme.border)
                    Text("Testing Limitations: \(analysis.testingLimitations)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func abuseAndCorrelationRow(finding: VulnerabilityFinding, analysis: AIAnalysisResult) -> some View {
        HStack(alignment: .top, spacing: 16) {
            SectionCard(title: "4. Security Implications & Conceptual Abuse", icon: "exclamationmark.Bubble.fill") {
                VStack(alignment: .leading, spacing: 8) {
                    Text(analysis.conceptualAbuseScenario)
                        .font(.subheadline)
                        .foregroundStyle(.white.opacity(0.9))
                    Divider().overlay(SentinelTheme.border)
                    Text("Direct Impact: \(finding.impact)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            SectionCard(title: "5. Correlated & Related Findings in Scope", icon: "point.3.connected.trianglepath.dotted") {
                Text(analysis.relatedFindingsAnalysis)
                    .font(.subheadline)
                    .foregroundStyle(.white.opacity(0.9))
            }
        }
    }

    private func validationAndRemediationCard(finding: VulnerabilityFinding, analysis: AIAnalysisResult) -> some View {
        SectionCard(title: "6. Controlled Validation Procedure, Secure Code Pattern & Fix Verification", icon: "hammer.fill") {
            VStack(alignment: .leading, spacing: 14) {
                Text("Controlled Safe Validation & Reproduction Procedure")
                    .font(.subheadline.weight(.bold))
                    .foregroundStyle(SentinelTheme.accentCyan)
                Text(analysis.controlledValidationProcedure)
                    .font(.subheadline)
                    .foregroundStyle(.white.opacity(0.92))
                    .textSelection(.enabled)

                Divider().overlay(SentinelTheme.border)

                Text("Recommended Secure Code & Configuration Pattern")
                    .font(.subheadline.weight(.bold))
                    .foregroundStyle(.green)
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
    }
}
