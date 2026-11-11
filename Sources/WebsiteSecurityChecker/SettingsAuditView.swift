import SwiftUI
import SentinelKit

public struct SettingsAuditView: View {
    @ObservedObject var vm: AppViewModel

    public init(vm: AppViewModel) {
        self.vm = vm
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("AI Analyst Configuration & Security Audit Logs")
                    .font(.system(size: 26, weight: .bold))
                    .foregroundStyle(.white)

                aiConfigurationSection
                scoringReferenceSection
                auditLogSection
            }
            .padding(24)
        }
        .background(SentinelTheme.bgPrimary)
    }

    private var aiConfigurationSection: some View {
        SectionCard(title: "AI Security Analyst Configuration (macOS Keychain)", icon: "key.fill") {
            VStack(alignment: .leading, spacing: 12) {
                Text("Website Security Checker works out of the box without any external API key using its built-in Deterministic Security Analyst. Optionally configure an OpenAI, Anthropic, or Google Gemini API key below to enable enhanced cloud LLM commentary.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                HStack(spacing: 16) {
                    Picker("AI Provider", selection: $vm.selectedAIProvider) {
                        ForEach(AIProvider.allCases, id: \.self) { prov in
                            Text(prov.rawValue).tag(prov)
                        }
                    }
                    .frame(width: 240)
                    .onChange(of: vm.selectedAIProvider) {
                        vm.refreshKeychainStatus()
                    }

                    TextField("Model ID", text: $vm.aiModelInput)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 220)

                    HStack(spacing: 6) {
                        Circle()
                            .fill(vm.hasSavedAPIKey ? Color.green : Color.orange)
                            .frame(width: 8, height: 8)
                        Text(vm.hasSavedAPIKey ? "Key Stored in macOS Keychain" : "Using Offline Deterministic Mode")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.white)
                    }
                }

                Text(vm.selectedAIProvider.setupInstructions)
                    .font(.caption)
                    .foregroundStyle(SentinelTheme.accentCyan)

                HStack(spacing: 12) {
                    SecureField("Paste \(vm.selectedAIProvider.rawValue) API Key...", text: $vm.apiKeyInput)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 380)

                    Button("Save to Keychain") {
                        vm.saveAPIKeyToKeychain()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(SentinelTheme.accentCyan)

                    if vm.hasSavedAPIKey {
                        Button("Remove Key", role: .destructive) {
                            vm.removeAPIKeyFromKeychain()
                        }
                        .buttonStyle(.bordered)
                    }
                }

                if let msg = vm.aiSettingsStatus {
                    Text(msg)
                        .font(.caption)
                        .foregroundStyle(.green)
                }
            }
        }
    }

    private var scoringReferenceSection: some View {
        SectionCard(title: "Security Scoring & Grading Reference (0–100)", icon: "tablecells") {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("95–100: A+ (Excellent)").frame(maxWidth: .infinity, alignment: .leading)
                    Text("90–94: A (Very strong)").frame(maxWidth: .infinity, alignment: .leading)
                    Text("85–89: B+ (Good)").frame(maxWidth: .infinity, alignment: .leading)
                    Text("80–84: B (Above average)").frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(.caption.weight(.semibold))
                .foregroundStyle(.white)

                HStack {
                    Text("75–79: C+ (Moderate)").frame(maxWidth: .infinity, alignment: .leading)
                    Text("70–74: C (Needs improvement)").frame(maxWidth: .infinity, alignment: .leading)
                    Text("60–69: D (Weak)").frame(maxWidth: .infinity, alignment: .leading)
                    Text("0–59: F (Poor)").frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(.caption.weight(.semibold))
                .foregroundStyle(.white)
            }
        }
    }

    private var auditLogSection: some View {
        SectionCard(title: "Persistent Authorization & Safety Audit Logs (\(vm.auditLogs.count))", icon: "list.bullet.clipboard.fill") {
            if vm.auditLogs.isEmpty {
                Text("No audit log entries recorded yet.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(vm.auditLogs.prefix(50)) { entry in
                        HStack(alignment: .top, spacing: 12) {
                            Text(entry.timestamp.formatted(date: .numeric, time: .standard))
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                                .frame(width: 145, alignment: .leading)

                            Text(entry.action)
                                .font(.caption2.weight(.bold).monospaced())
                                .foregroundStyle(entry.action.contains("BLOCKED") || entry.action.contains("STOP") ? .orange : SentinelTheme.accentCyan)
                                .frame(width: 185, alignment: .leading)

                            Text(entry.targetDomain)
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.white)
                                .frame(width: 140, alignment: .leading)

                            Text(entry.details)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .padding(.vertical, 4)
                        Divider().overlay(SentinelTheme.border)
                    }
                }
            }
        }
    }
}
