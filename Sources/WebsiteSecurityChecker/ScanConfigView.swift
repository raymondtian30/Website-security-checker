import SwiftUI
import SentinelKit

public struct ScanConfigView: View {
    @ObservedObject var vm: AppViewModel

    public init(vm: AppViewModel) {
        self.vm = vm
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Scan Setup & Live Monitor")
                            .font(.system(size: 25, weight: .bold))
                            .foregroundStyle(.white)
                        Text("Configure your authorized target, hover over any '?' icon for guidance, and launch a security & malware scan.")
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

                if let err = vm.errorMessage {
                    SectionCard(title: "Scope / Authorization Notice", icon: "exclamationmark.octagon.fill") {
                        Text(err).font(.subheadline).foregroundStyle(.red)
                    }
                }

                if let banner = vm.statusBannerMessage {
                    SectionCard(title: "Ready", icon: "checkmark.seal.fill") {
                        Text(banner).font(.subheadline).foregroundStyle(.green)
                    }
                }

                // 1. Target & Authorization
                SectionCard(
                    title: "1. Target Website & Authorization",
                    icon: "lock.shield.fill",
                    helpText: "Enter the full URL (including https:// or http://) of the website you own or have permission to audit. Sentinel automatically extracts the domain and locks active requests to that scope."
                ) {
                    VStack(alignment: .leading, spacing: 14) {
                        HStack(spacing: 16) {
                            VStack(alignment: .leading, spacing: 6) {
                                HStack(spacing: 5) {
                                    Text("Target Website URL")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.secondary)
                                    HelpTooltip("Target URL", explanation: "The starting webpage URL to audit (e.g., https://example.com). Sentinel will crawl in-scope links starting from this address.")
                                }
                                TextField("https://example.com", text: $vm.scanConfig.targetURL)
                                    .textFieldStyle(.roundedBorder)
                                    .onChange(of: vm.scanConfig.targetURL) {
                                        vm.syncDomainFromTargetURL()
                                    }
                            }
                            VStack(alignment: .leading, spacing: 6) {
                                HStack(spacing: 5) {
                                    Text("Authorized Root Domain")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.secondary)
                                    HelpTooltip("Authorized Root Domain", explanation: "Sentinel's C++ ScopeGuard blocks any request or redirect that tries to leave this domain, protecting against out-of-scope testing and SSRF.")
                                }
                                TextField("example.com", text: $vm.scanConfig.targetDomain)
                                    .textFieldStyle(.roundedBorder)
                            }
                        }

                        HStack(spacing: 10) {
                            Text("Built-In Practice Targets:")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                            HelpTooltip("Built-In Practice Targets", explanation: "Starts a safe local web server on your Mac (127.0.0.1) so you can immediately test how Sentinel detects real vulnerabilities and malware vs. a hardened A+ site.")

                            Button("Load Vulnerable & Malware Target") {
                                vm.configureLocalPracticeTarget(vulnerable: true)
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)

                            Button("Load Hardened Safe (A+) Target") {
                                vm.configureLocalPracticeTarget(vulnerable: false)
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        }

                        Toggle(isOn: $vm.scanConfig.authorized) {
                            HStack(spacing: 6) {
                                Text("I confirm that I own this target domain or have explicit written authorization to audit it.")
                                    .font(.subheadline.weight(.semibold))
                                    .foregroundStyle(.white)
                                HelpTooltip("Mandatory Authorization", explanation: "Required before any scan can start. Every scan attestation is logged to your local SQLite Audit Log.")
                            }
                        }
                        .toggleStyle(.checkbox)
                        .padding(10)
                        .background(SentinelTheme.bgElevated)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                }

                // 2. Scope & Safety Controls
                SectionCard(
                    title: "2. Scope Boundaries & Scan Intensity",
                    icon: "slider.horizontal.3",
                    helpText: "Fine-tune which subdomains and paths are in scope, how thorough the scan should be, and how many requests per second are allowed."
                ) {
                    VStack(alignment: .leading, spacing: 14) {
                        HStack(spacing: 16) {
                            VStack(alignment: .leading, spacing: 6) {
                                HStack(spacing: 5) {
                                    Text("Allowed Subdomains")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.secondary)
                                    HelpTooltip("Allowed Subdomains", explanation: "Comma-separated list of additional subdomains (e.g., api.example.com, shop.example.com) that the scanner is permitted to test.")
                                }
                                TextField("api.example.com, app.example.com", text: $vm.allowedSubdomainsInput)
                                    .textFieldStyle(.roundedBorder)
                            }
                            VStack(alignment: .leading, spacing: 6) {
                                HStack(spacing: 5) {
                                    Text("Excluded Paths")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.secondary)
                                    HelpTooltip("Excluded Paths", explanation: "URL paths the scanner will never visit (such as /logout or /delete) to avoid terminating sessions or triggering unwanted actions.")
                                }
                                TextField("/logout, /signout, /delete", text: $vm.excludedPathsInput)
                                    .textFieldStyle(.roundedBorder)
                            }
                        }

                        HStack(spacing: 24) {
                            HStack(spacing: 5) {
                                Toggle("Include All Subdomains", isOn: $vm.scanConfig.includeSubdomains)
                                    .toggleStyle(.checkbox)
                                HelpTooltip("Include All Subdomains", explanation: "When enabled, any *.targetdomain.com subdomain discovered during crawling is permitted in scope.")
                            }
                            HStack(spacing: 5) {
                                Toggle("Local Testbench Mode (127.0.0.1)", isOn: $vm.scanConfig.allowLocalTestbench)
                                    .toggleStyle(.checkbox)
                                HelpTooltip("Local Testbench Mode", explanation: "By default, Sentinel blocks localhost (127.0.0.1) to prevent SSRF. Enable this only when testing a local server running on your Mac on port >= 1024.")
                            }
                        }
                        .font(.caption)

                        Divider().overlay(SentinelTheme.border)

                        HStack(spacing: 24) {
                            VStack(alignment: .leading, spacing: 6) {
                                HStack(spacing: 5) {
                                    Text("Scan Intensity")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.secondary)
                                    HelpTooltip("Scan Intensity", explanation: "• Passive: Only inspects headers, cookies, TLS, and HTML on initial pages.\n• Standard: Crawls in-scope pages and runs non-destructive indicator checks.\n• Thorough: Deep crawling + full injection, malware, plugin, DDoS posture, and config checks.")
                                }
                                Picker("Scan Intensity", selection: $vm.scanConfig.intensity) {
                                    ForEach(ScanIntensity.allCases, id: \.rawValue) { level in
                                        Text(level.rawValue).tag(level.rawValue)
                                    }
                                }
                                .labelsHidden()
                                .pickerStyle(.segmented)
                                .frame(width: 260)
                            }

                            VStack(alignment: .leading, spacing: 6) {
                                HStack(spacing: 5) {
                                    Text("Rate Limit: \(vm.scanConfig.maxRequestsPerSecond) req/s")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.secondary)
                                    HelpTooltip("Request Rate Limit", explanation: "Caps the maximum HTTP requests per second sent by the C++ engine so the target server is never overwhelmed.")
                                }
                                Slider(
                                    value: Binding(
                                        get: { Double(vm.scanConfig.maxRequestsPerSecond) },
                                        set: { vm.scanConfig.maxRequestsPerSecond = Int($0) }
                                    ),
                                    in: 1...25,
                                    step: 1
                                )
                                .frame(width: 165)
                            }

                            VStack(alignment: .leading, spacing: 6) {
                                HStack(spacing: 5) {
                                    Text("Max Duration: \(vm.scanConfig.maxDurationSeconds)s")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.secondary)
                                    HelpTooltip("Maximum Scan Duration", explanation: "Hard time limit for the assessment. If reached, remaining checks are cleanly stopped and marked Incomplete.")
                                }
                                Slider(
                                    value: Binding(
                                        get: { Double(vm.scanConfig.maxDurationSeconds) },
                                        set: { vm.scanConfig.maxDurationSeconds = Int($0) }
                                    ),
                                    in: 15...600,
                                    step: 15
                                )
                                .frame(width: 165)
                            }
                        }
                    }
                }

                // 3. Scan Modules
                SectionCard(
                    title: "3. Active Security & Malware Engines (11 Modules)",
                    icon: "cpu.fill",
                    helpText: "Select which vulnerability and threat engines to run. Includes SQL/NoSQL/SSTI/XXE/LFI Injections, XSS & Prototype Pollution, Cookie Theft & Auth Attacks, Malware & Skimmers, DDoS Resilience, Plugin Vulnerabilities, and DNS Spoofing Posture."
                ) {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 220))], alignment: .leading, spacing: 10) {
                        ForEach(ScanCategory.allCases) { cat in
                            Toggle(cat.rawValue, isOn: Binding(
                                get: { vm.scanConfig.enabledCategories.contains(cat.rawValue) },
                                set: { enabled in
                                    if enabled {
                                        if !vm.scanConfig.enabledCategories.contains(cat.rawValue) {
                                            vm.scanConfig.enabledCategories.append(cat.rawValue)
                                        }
                                    } else if vm.scanConfig.enabledCategories.count > 1 {
                                        vm.scanConfig.enabledCategories.removeAll { $0 == cat.rawValue }
                                    }
                                }
                            ))
                            .toggleStyle(.checkbox)
                            .font(.subheadline)
                        }
                    }
                }

                // 4. Launch Controls & Live Progress
                HStack(spacing: 14) {
                    Button {
                        vm.startScan()
                    } label: {
                        Label(vm.isScanning ? "Scan Running..." : "Start Authorized Security Scan", systemImage: "bolt.shield.fill")
                            .font(.headline)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 6)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(SentinelTheme.accentCyan)
                    .disabled(vm.isScanning)

                    if vm.isScanning {
                        Button {
                            vm.togglePauseScan()
                        } label: {
                            Label(vm.isPaused ? "Resume" : "Pause", systemImage: vm.isPaused ? "play.fill" : "pause.fill")
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                        }
                        .buttonStyle(.bordered)

                        Button(role: .destructive) {
                            vm.emergencyStopScan()
                        } label: {
                            Label("EMERGENCY STOP", systemImage: "xmark.octagon.fill")
                                .font(.headline)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.red)
                    }
                }

                if vm.isScanning || vm.liveProgress.checksCompleted > 0 {
                    SectionCard(title: "Live Engine Telemetry", icon: "waveform.path.ecg.rectangle") {
                        VStack(alignment: .leading, spacing: 10) {
                            HStack {
                                Text("Module: \(vm.liveProgress.currentModule) (\(vm.liveProgress.status))")
                                    .font(.subheadline.weight(.semibold))
                                    .foregroundStyle(.white)
                                Spacer()
                                Text("Coverage: \(String(format: "%.0f%%", vm.liveProgress.coveragePercent)) • Endpoints: \(vm.liveProgress.endpointsExamined) • Findings: \(vm.liveProgress.findingsCount)")
                                    .font(.caption)
                                    .foregroundStyle(SentinelTheme.accentCyan)
                            }
                            ProgressView(value: vm.liveProgress.coveragePercent, total: 100.0)
                                .tint(SentinelTheme.accentCyan)
                        }
                    }
                }
            }
            .padding(24)
        }
        .background(SentinelTheme.bgPrimary)
    }
}
