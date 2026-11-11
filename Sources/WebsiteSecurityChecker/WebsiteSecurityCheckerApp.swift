import SwiftUI
import AppKit
import SentinelKit

@main
struct WebsiteSecurityCheckerApp: App {
    @StateObject private var vm = AppViewModel()

    init() {
        NSApplication.shared.setActivationPolicy(.regular)
    }

    var body: some Scene {
        WindowGroup("Sentinal") {
            MainContentView(vm: vm)
                .frame(minWidth: 1080, minHeight: 720)
                .preferredColorScheme(.dark)
                .sheet(isPresented: $vm.showStepByStepGuide) {
                    StepByStepGuideSheet(vm: vm)
                }
        }
        .windowResizability(.contentMinSize)
    }
}

struct MainContentView: View {
    @ObservedObject var vm: AppViewModel

    var body: some View {
        NavigationSplitView {
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 10) {
                    Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                        .font(.system(size: 24, weight: .bold))
                        .foregroundStyle(SentinelTheme.accentCyan)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("SENTINAL")
                            .font(.system(size: 16, weight: .heavy, design: .rounded))
                            .foregroundStyle(.white)
                        Text("v\(SettingsAuditView.currentVersion) • Security & Malware")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(16)

                Divider().overlay(SentinelTheme.border)

                List(NavigationTab.allCases, selection: $vm.selectedTab) { tab in
                    Label(tab.rawValue, systemImage: tab.icon)
                        .tag(tab)
                }
                .listStyle(.sidebar)

                Spacer()

                if let scan = vm.activeScan {
                    let safety = SecurityScorer.evaluateVisitorSafety(
                        findings: scan.findings,
                        overallScore: scan.scoreBreakdown.overallScore
                    )
                    VStack(alignment: .leading, spacing: 6) {
                        Text("ACTIVE TARGET")
                            .font(.system(size: 9.5, weight: .bold))
                            .foregroundStyle(.secondary)
                        Text(scan.targetDomain)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.white)
                            .lineLimit(1)
                        HStack {
                            Text("Security: \(scan.scoreBreakdown.overallScore)")
                            Spacer()
                            Text(scan.scoreBreakdown.letterGrade)
                                .bold()
                                .foregroundStyle(SentinelTheme.gradeColor(scan.scoreBreakdown.overallScore))
                        }
                        .font(.caption2)
                        HStack {
                            Text("Visitor Safety: \(safety.safetyScore)")
                            Spacer()
                            Text(safety.safetyGrade)
                                .bold()
                                .foregroundStyle(SentinelTheme.gradeColor(safety.safetyScore))
                        }
                        .font(.caption2)
                    }
                    .padding(11)
                    .background(SentinelTheme.bgCard)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .padding(.horizontal, 12)
                    .padding(.bottom, 8)
                }

                HStack {
                    Text("Sentinal v\(SettingsAuditView.currentVersion)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button {
                        vm.showStepByStepGuide = true
                    } label: {
                        Image(systemName: "questionmark.circle.fill")
                            .foregroundStyle(SentinelTheme.accentCyan)
                    }
                    .buttonStyle(.plain)
                    .help("Open Step-by-Step Guide")
                }
                .padding(.horizontal, 14)
                .padding(.bottom, 12)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 210, max: 230)
            .background(SentinelTheme.bgPrimary)
        } detail: {
            Group {
                switch vm.selectedTab {
                case .dashboard:
                    DashboardView(vm: vm)
                case .scanConfig:
                    ScanConfigView(vm: vm)
                case .malwareScanner:
                    MalwareScannerView(vm: vm)
                case .findings:
                    FindingsView(vm: vm)
                case .history:
                    HistoryComparisonView(vm: vm)
                case .settings:
                    SettingsAuditView(vm: vm)
                }
            }
            .navigationSplitViewColumnWidth(min: 780, ideal: 980)
        }
    }
}
