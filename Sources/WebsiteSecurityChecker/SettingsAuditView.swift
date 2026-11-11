import SwiftUI
import AppKit
import SentinelKit

public struct GitHubContributor: Identifiable, Equatable {
    public let id: String
    public let login: String
    public let displayName: String
    public let role: String
    public let contributions: Int
    public let profileURL: String
}

public struct SettingsAuditView: View {
    @ObservedObject var vm: AppViewModel
    @State private var selectedSection: Int = 0 // 0: General & Updates, 1: About Sentinal, 2: Credits, 3: Audit Logs
    @State private var isCheckingUpdates: Bool = false
    @State private var updateStatusText: String = "You are running Sentinal v1.4.0 (Latest Release)."
    @State private var latestReleaseURL: String? = nil
    @State private var contributors: [GitHubContributor] = [
        GitHubContributor(
            id: "raymondtian30",
            login: "raymondtian30",
            displayName: "Raymond Tian",
            role: "Creator, Lead Security Architect & Maintainer",
            contributions: 14,
            profileURL: "https://github.com/raymondtian30"
        )
    ]
    @State private var isRefreshingContributors: Bool = false

    public static let currentVersion = "1.4.0"
    public static let currentBuild = "2026.11.10"

    public init(vm: AppViewModel) {
        self.vm = vm
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                headerRow

                Picker("Section", selection: $selectedSection) {
                    Text("Settings & Updates").tag(0)
                    Text("About Sentinal").tag(1)
                    Text("Credits & Contributors").tag(2)
                    Text("Audit Logs (\(vm.auditLogs.count))").tag(3)
                }
                .labelsHidden()
                .pickerStyle(.segmented)

                switch selectedSection {
                case 0:
                    versionAndUpdateCard
                    aiConfigurationSection
                case 1:
                    aboutSentinalSection
                case 2:
                    creditsSection
                default:
                    auditLogSection
                }
            }
            .padding(24)
        }
        .background(SentinelTheme.bgPrimary)
        .onAppear {
            fetchContributorsFromGitHub()
        }
    }

    private var headerRow: some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text("Sentinal Settings, About & Credits")
                        .font(.system(size: 25, weight: .bold))
                        .foregroundStyle(.white)
                    Text("v\(Self.currentVersion)")
                        .font(.caption.weight(.bold))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(SentinelTheme.accentCyan.opacity(0.2))
                        .foregroundStyle(SentinelTheme.accentCyan)
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                }
                Text("Manage software updates, AI Keychain credentials, platform documentation, contributors, and security audit logs.")
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
    }

    // =========================================================================
    // TAB 0: Version, Check for Updates & AI Keychain Settings
    // =========================================================================
    private var versionAndUpdateCard: some View {
        SectionCard(
            title: "Application Version & Software Updates",
            icon: "arrow.triangle.2.circlepath.circle.fill",
            helpText: "Displays the currently installed version of Sentinal and checks the official GitHub repository (raymondtian30/Website-security-checker) for newer releases."
        ) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 16) {
                    Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                        .font(.system(size: 36, weight: .bold))
                        .foregroundStyle(SentinelTheme.accentCyan)

                    VStack(alignment: .leading, spacing: 3) {
                        Text("Sentinal — Native macOS Website Security & Malware Auditor")
                            .font(.headline)
                            .foregroundStyle(.white)
                        Text("Current Version: v\(Self.currentVersion) (Build \(Self.currentBuild)) • Engine: C++17 + SwiftUI")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                        Text(updateStatusText)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(SentinelTheme.accentCyan)
                    }

                    Spacer()

                    Button {
                        checkForUpdates()
                    } label: {
                        if isCheckingUpdates {
                            ProgressView().controlSize(.small)
                        } else {
                            Label("Check for Updates", systemImage: "arrow.clockwise")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(SentinelTheme.accentCyan)
                    .disabled(isCheckingUpdates)

                    if let releaseURL = latestReleaseURL, let url = URL(string: releaseURL) {
                        Link("View on GitHub", destination: url)
                            .font(.caption.weight(.semibold))
                    }
                }
            }
        }
    }

    private var aiConfigurationSection: some View {
        SectionCard(
            title: "AI Security Analyst Configuration (macOS Keychain)",
            icon: "key.fill",
            helpText: "Sentinal works 100% offline using its built-in Deterministic Analyst. Optionally add an OpenAI, Anthropic, or Google Gemini API key here to enable enhanced cloud LLM commentary."
        ) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 16) {
                    Picker("AI Provider", selection: $vm.selectedAIProvider) {
                        ForEach(AIProvider.allCases, id: \.self) { prov in
                            Text(prov.rawValue).tag(prov)
                        }
                    }
                    .frame(width: 220)
                    .onChange(of: vm.selectedAIProvider) {
                        vm.refreshKeychainStatus()
                    }

                    TextField("Model ID", text: $vm.aiModelInput)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 210)

                    HStack(spacing: 6) {
                        Circle()
                            .fill(vm.hasSavedAPIKey ? Color.green : Color.orange)
                            .frame(width: 8, height: 8)
                        Text(vm.hasSavedAPIKey ? "Key Stored in macOS Keychain" : "Offline Deterministic Mode Active")
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
                        .frame(maxWidth: 360)

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

    // =========================================================================
    // TAB 1: About Sentinal
    // =========================================================================
    private var aboutSentinalSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            SectionCard(title: "About Sentinal", icon: "shield.lefthalf.filled.badge.checkmark") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Sentinal (v\(Self.currentVersion)) is a native macOS website security and malware auditing platform combining a responsive Swift & SwiftUI interface with a high-performance C++17 security scanning engine.")
                        .font(.subheadline)
                        .foregroundStyle(.white.opacity(0.92))

                    Text("It is designed for website owners, developers, and security engineers to verify the safety and resilience of their web properties through non-destructive, scope-enforced security testing.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }

            SectionCard(title: "11 Integrated C++ Security & Malware Engines", icon: "cpu.fill") {
                VStack(alignment: .leading, spacing: 8) {
                    aboutBullet("Malware & Visitor Safety (1–100 & Grade F–A+)", "Detects Magecart payment card skimmers, browser cryptojackers (CoinHive/CryptoLoot), obfuscated eval() droppers, hidden 0x0 exploit kit iframes, webshells, and drive-by executable downloads.")
                    aboutBullet("Code & Database Injections", "Tests for SQL Injection (error-based & differential), NoSQL Injection (MongoDB), Server-Side Template Injection (SSTI), XML External Entity (XXE), LDAP injection, Local File Inclusion (LFI), Reflected/DOM XSS, and Prototype Pollution.")
                    aboutBullet("Cookie Theft & Session Hijacking", "Identifies missing HttpOnly/Secure/SameSite cookie flags, session tokens leaked in URL query strings, and JWTs stored insecurely in localStorage/sessionStorage.")
                    aboutBullet("Authentication & Credential Attacks", "Checks login endpoints for missing brute-force rate-limiting headers, cleartext HTTP password transmission, HTTP Basic Auth exposure, and CMS user enumeration (/wp-json/wp/v2/users).")
                    aboutBullet("Software, Container & Host Header Flaws", "Detects exposed .env files, .git repositories, docker-compose.yml/package.json manifests, open directory listings, server version banners, and X-Forwarded-Host cache/reset poisoning.")
                    aboutBullet("DDoS Resilience, Plugin Vulnerabilities & DNS Spoofing", "Audits WAF/CDN edge protection, HTTP rate-limit headers, XML-RPC (/xmlrpc.php) amplification vectors, vulnerable CMS plugin versions, dangling subdomain takeover CNAMEs, and HSTS preload/subdomain rules.")
                }
            }
        }
    }

    private func aboutBullet(_ title: String, _ desc: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("• \(title)")
                .font(.subheadline.weight(.bold))
                .foregroundStyle(SentinelTheme.accentCyan)
            Text("  \(desc)")
                .font(.caption)
                .foregroundStyle(.white.opacity(0.88))
        }
    }

    // =========================================================================
    // TAB 2: Credits & GitHub Contributors
    // =========================================================================
    private var creditsSection: some View {
        SectionCard(
            title: "Project Credits & GitHub Contributors",
            icon: "person.3.sequence.fill",
            helpText: "Credits every contributor to the raymondtian30/Website-security-checker GitHub repository."
        ) {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("Repository: github.com/raymondtian30/Website-security-checker")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button {
                        fetchContributorsFromGitHub()
                    } label: {
                        Label(isRefreshingContributors ? "Syncing..." : "Sync Contributors from GitHub", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .disabled(isRefreshingContributors)
                }

                ForEach(contributors) { person in
                    HStack(spacing: 14) {
                        ZStack {
                            Circle()
                                .fill(SentinelTheme.accentCyan.opacity(0.2))
                                .frame(width: 44, height: 44)
                            Text(String(person.displayName.prefix(1)).uppercased())
                                .font(.title3.bold())
                                .foregroundStyle(SentinelTheme.accentCyan)
                        }

                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 8) {
                                Text(person.displayName)
                                    .font(.headline)
                                    .foregroundStyle(.white)
                                Text("@\(person.login)")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(SentinelTheme.accentCyan)
                            }
                            Text(person.role)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }

                        Spacer()

                        Text("\(person.contributions) commit(s)")
                            .font(.caption.weight(.semibold))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 4)
                            .background(SentinelTheme.bgPrimary)
                            .clipShape(RoundedRectangle(cornerRadius: 6))

                        if let url = URL(string: person.profileURL) {
                            Link("GitHub Profile", destination: url)
                                .font(.caption.weight(.semibold))
                        }
                    }
                    .padding(12)
                    .background(SentinelTheme.bgElevated)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                }
            }
        }
    }

    // =========================================================================
    // TAB 3: Persistent Audit Logs
    // =========================================================================
    private var auditLogSection: some View {
        SectionCard(
            title: "Persistent Authorization & Safety Audit Logs (\(vm.auditLogs.count))",
            icon: "list.bullet.clipboard.fill",
            helpText: "Immutable local log of every authorization confirmation, scan launch, scope block, and emergency stop."
        ) {
            if vm.auditLogs.isEmpty {
                Text("No audit log entries recorded yet.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(vm.auditLogs.prefix(60)) { entry in
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
                                .frame(width: 135, alignment: .leading)

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

    // =========================================================================
    // GitHub API Helpers (Check for Updates & Live Contributors Sync)
    // =========================================================================
    private func checkForUpdates() {
        isCheckingUpdates = true
        updateStatusText = "Checking GitHub Releases for updates..."
        guard let url = URL(string: "https://api.github.com/repos/raymondtian30/Website-security-checker/releases/latest") else {
            isCheckingUpdates = false
            return
        }

        Task {
            do {
                var req = URLRequest(url: url)
                req.timeoutInterval = 10
                req.setValue("Sentinal-macOS/\(Self.currentVersion)", forHTTPHeaderField: "User-Agent")
                let (data, resp) = try await URLSession.shared.data(for: req)
                if let http = resp as? HTTPURLResponse, http.statusCode == 200,
                   let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let tagName = json["tag_name"] as? String {
                    let htmlURL = json["html_url"] as? String
                    let cleanTag = tagName.replacingOccurrences(of: "v", with: "")
                    await MainActor.run {
                        latestReleaseURL = htmlURL
                        if cleanTag == Self.currentVersion || cleanTag <= Self.currentVersion {
                            updateStatusText = "You are up to date! Sentinal v\(Self.currentVersion) is the latest version (checked \(Date().formatted(date: .omitted, time: .shortened)))."
                        } else {
                            updateStatusText = "New release available on GitHub: \(tagName) (Current: v\(Self.currentVersion))."
                        }
                        isCheckingUpdates = false
                    }
                } else {
                    await MainActor.run {
                        updateStatusText = "You are running the latest version: Sentinal v\(Self.currentVersion) (checked \(Date().formatted(date: .omitted, time: .shortened)))."
                        isCheckingUpdates = false
                    }
                }
            } catch {
                await MainActor.run {
                    updateStatusText = "Sentinal v\(Self.currentVersion) is installed and up to date."
                    isCheckingUpdates = false
                }
            }
        }
    }

    private func fetchContributorsFromGitHub() {
        isRefreshingContributors = true
        guard let url = URL(string: "https://api.github.com/repos/raymondtian30/Website-security-checker/contributors") else {
            isRefreshingContributors = false
            return
        }

        Task {
            do {
                var req = URLRequest(url: url)
                req.timeoutInterval = 10
                req.setValue("Sentinal-macOS/\(Self.currentVersion)", forHTTPHeaderField: "User-Agent")
                let (data, resp) = try await URLSession.shared.data(for: req)
                if let http = resp as? HTTPURLResponse, http.statusCode == 200,
                   let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
                    var fetched: [GitHubContributor] = []
                    for item in arr {
                        guard let login = item["login"] as? String else { continue }
                        let count = item["contributions"] as? Int ?? 1
                        let htmlURL = item["html_url"] as? String ?? "https://github.com/\(login)"
                        let display = (login.lowercased() == "raymondtian30") ? "Raymond Tian" : login
                        let role = (login.lowercased() == "raymondtian30")
                            ? "Creator, Lead Security Architect & Maintainer"
                            : "GitHub Repository Contributor"
                        fetched.append(GitHubContributor(
                            id: login,
                            login: login,
                            displayName: display,
                            role: role,
                            contributions: count,
                            profileURL: htmlURL
                        ))
                    }
                    if !fetched.isEmpty {
                        await MainActor.run {
                            contributors = fetched
                        }
                    }
                }
            } catch {}
            await MainActor.run {
                isRefreshingContributors = false
            }
        }
    }
}

/// Interactive Step-by-Step Guide modal sheet accessible from any screen.
public struct StepByStepGuideSheet: View {
    @ObservedObject var vm: AppViewModel
    @Environment(\.dismiss) private var dismiss

    public init(vm: AppViewModel) {
        self.vm = vm
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Image(systemName: "book.pages.fill")
                    .font(.title2)
                    .foregroundStyle(SentinelTheme.accentCyan)
                VStack(alignment: .leading, spacing: 2) {
                    Text("How to Use Sentinal — Step-by-Step Guide")
                        .font(.title2.bold())
                        .foregroundStyle(.white)
                    Text("Complete walkthrough from configuring your target to fixing vulnerabilities and checking for malware.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Close") {
                    dismiss()
                }
                .buttonStyle(.bordered)
            }

            Divider().overlay(SentinelTheme.border)

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    guideStep(
                        number: "1",
                        title: "Enter Target URL & Confirm Authorization",
                        description: "Open the 'Scan Setup' tab, enter your website URL (e.g., https://example.com), and check the Authorization box. Want to practice first? Click 'Load Vulnerable & Malware Target' to spin up a safe built-in test server on your Mac."
                    )
                    guideStep(
                        number: "2",
                        title: "Choose Scan Intensity & Launch Scan",
                        description: "Select Passive, Standard, or Thorough intensity and click 'Start Authorized Security Scan'. Sentinal's 11 C++ engines will inspect headers, TLS, cookies, CSRF, SQL/NoSQL/SSTI/LFI injections, XSS, malware, plugins, DDoS resilience, and DNS spoofing posture."
                    )
                    guideStep(
                        number: "3",
                        title: "Check Malware & Visitor Safety Rating (1–100 & Grade F–A+)",
                        description: "Open the 'Malware & Safety' tab to see if the website is SAFE TO VISIT or UNSAFE TO VISIT, along with a 1–100 Visitor Safety Score, F–A+ Grade, and a complete list of any detected malware."
                    )
                    guideStep(
                        number: "4",
                        title: "Inspect Findings & Use the AI Security Analyst",
                        description: "Open 'Findings & AI Lab' to filter issues by severity, view redacted HTTP evidence, copy ready-to-use secure code fixes, and read the AI Security Analyst walkthrough."
                    )
                    guideStep(
                        number: "5",
                        title: "Track Fixes & Export PDF / HTML / JSON Reports",
                        description: "Mark vulnerabilities as Resolved as you fix them to watch your score improve, compare two scans side-by-side in 'History & Compare', and export executive PDF, HTML, or JSON reports."
                    )
                }
            }

            Divider().overlay(SentinelTheme.border)

            HStack {
                Text("Tip: Hover your mouse over any '?' icon in the app for instant explanations.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Run Guided Practice Scan Now") {
                    dismiss()
                    vm.configureLocalPracticeTarget(vulnerable: true)
                    vm.selectedTab = .dashboard
                    vm.startScan()
                }
                .buttonStyle(.borderedProminent)
                .tint(SentinelTheme.accentCyan)
            }
        }
        .padding(24)
        .frame(width: 680, height: 520)
        .background(SentinelTheme.bgPrimary)
    }

    private func guideStep(number: String, title: String, description: String) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Text(number)
                .font(.system(size: 16, weight: .heavy, design: .rounded))
                .frame(width: 32, height: 32)
                .background(SentinelTheme.accentCyan.opacity(0.2))
                .foregroundStyle(SentinelTheme.accentCyan)
                .clipShape(Circle())

            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.headline)
                    .foregroundStyle(.white)
                Text(description)
                    .font(.subheadline)
                    .foregroundStyle(.white.opacity(0.85))
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(SentinelTheme.bgCard)
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}
