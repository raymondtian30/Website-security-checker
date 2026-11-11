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
        WindowGroup("Website Security Checker — Sentinel Platform") {
            MainContentView(vm: vm)
                .frame(minWidth: 1120, minHeight: 740)
                .preferredColorScheme(.dark)
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
                        Text("SENTINEL")
                            .font(.system(size: 15, weight: .heavy, design: .rounded))
                            .foregroundStyle(.white)
                        Text("Security Auditor")
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
                    VStack(alignment: .leading, spacing: 6) {
                        Text("ACTIVE ASSESSMENT")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundStyle(.secondary)
                        Text(scan.targetDomain)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.white)
                            .lineLimit(1)
                        HStack {
                            Text("Score: \(scan.scoreBreakdown.overallScore)/100")
                            Spacer()
                            Text("Grade \(scan.scoreBreakdown.letterGrade)")
                                .bold()
                                .foregroundStyle(SentinelTheme.gradeColor(scan.scoreBreakdown.overallScore))
                        }
                        .font(.caption2)
                    }
                    .padding(12)
                    .background(SentinelTheme.bgCard)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .padding(12)
                }
            }
            .navigationSplitViewColumnWidth(min: 175, ideal: 205, max: 225)
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
                case .investigation:
                    InvestigationView(vm: vm)
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
