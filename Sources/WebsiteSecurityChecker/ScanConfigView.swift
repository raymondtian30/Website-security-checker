import SwiftUI
import SentinelKit

public struct ScanConfigView: View {
    @ObservedObject var vm: AppViewModel

    public init(vm: AppViewModel) {
        self.vm = vm
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Scan Configuration & Live Telemetry")
                    .font(.system(size: 26, weight: .bold))
                    .foregroundStyle(.white)

                if let err = vm.errorMessage {
                    SectionCard(title: "Authorization / Scope Alert", icon: "exclamationmark.octagon.fill") {
                        Text(err)
                            .font(.subheadline)
                            .foregroundStyle(.red)
                    }
                }

                if let banner = vm.statusBannerMessage {
                    SectionCard(title: "Assessment Status", icon: "checkmark.seal.fill") {
                        Text(banner)
                            .font(.subheadline)
                            .foregroundStyle(.green)
                    }
                }

                // 1. Target & Mandatory Authorization
                SectionCard(title: "1. Target Domain & Mandatory Authorization", icon: "lock.shield.fill") {
                    VStack(alignment: .leading, spacing: 14) {
                        HStack(spacing: 16) {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Target Website URL")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.secondary)
                                TextField("https://example.com", text: $vm.scanConfig.targetURL)
                                    .textFieldStyle(.roundedBorder)
                                    .onChange(of: vm.scanConfig.targetURL) {
                                        vm.syncDomainFromTargetURL()
                                    }
                            }
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Explicitly Authorized Domain")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.secondary)
                                TextField("example.com", text: $vm.scanConfig.targetDomain)
                                    .textFieldStyle(.roundedBorder)
                            }
                        }

                        Toggle(isOn: $vm.scanConfig.authorized) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("I confirm that I own this target domain or have explicit written permission to perform this security assessment.")
                                    .font(.subheadline.weight(.semibold))
                                    .foregroundStyle(.white)
                                Text("Required before every scan. All requests are logged to the local persistent Audit Log and strictly confined to the authorized scope.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .toggleStyle(.checkbox)
                        .padding(10)
                        .background(SentinelTheme.bgElevated)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                }

                // 2. Scope Boundaries & Rate Limits
                SectionCard(title: "2. Scope Boundaries, Intensity & Safety Limits", icon: "slider.horizontal.3") {
                    VStack(alignment: .leading, spacing: 14) {
                        HStack(spacing: 16) {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Allowed Subdomains (comma-separated)")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.secondary)
                                TextField("api.example.com, app.example.com", text: $vm.allowedSubdomainsInput)
                                    .textFieldStyle(.roundedBorder)
                            }
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Excluded Paths (comma-separated)")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.secondary)
                                TextField("/logout, /signout, /delete", text: $vm.excludedPathsInput)
                                    .textFieldStyle(.roundedBorder)
                            }
                        }

                        HStack(spacing: 24) {
                            Toggle("Allow All Subdomains of Target Domain", isOn: $vm.scanConfig.includeSubdomains)
                                .toggleStyle(.checkbox)
                            Toggle("Local Testbench Mode (Allow 127.0.0.1 >=1024 for local QA servers)", isOn: $vm.scanConfig.allowLocalTestbench)
                                .toggleStyle(.checkbox)
                        }
                        .font(.caption)

                        Divider().overlay(SentinelTheme.border)

                        HStack(spacing: 24) {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Scan Intensity")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.secondary)
                                Picker("Scan Intensity", selection: $vm.scanConfig.intensity) {
                                    ForEach(ScanIntensity.allCases, id: \.rawValue) { level in
                                        Text(level.rawValue).tag(level.rawValue)
                                    }
                                }
                                .pickerStyle(.segmented)
                                .frame(width: 280)
                            }

                            VStack(alignment: .leading, spacing: 6) {
                                Text("Rate Limit: \(vm.scanConfig.maxRequestsPerSecond) req/sec")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.secondary)
                                Slider(
                                    value: Binding(
                                        get: { Double(vm.scanConfig.maxRequestsPerSecond) },
                                        set: { vm.scanConfig.maxRequestsPerSecond = Int($0) }
                                    ),
                                    in: 1...25,
                                    step: 1
                                )
                                .frame(width: 180)
                            }

                            VStack(alignment: .leading, spacing: 6) {
                                Text("Max Duration: \(vm.scanConfig.maxDurationSeconds)s")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.secondary)
                                Slider(
                                    value: Binding(
                                        get: { Double(vm.scanConfig.maxDurationSeconds) },
                                        set: { vm.scanConfig.maxDurationSeconds = Int($0) }
                                    ),
                                    in: 15...600,
                                    step: 15
                                )
                                .frame(width: 180)
                            }
                        }
                    }
                }

                // 3. Scan Categories
                SectionCard(title: "3. Security Audit Modules", icon: "checklist") {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 210))], alignment: .leading, spacing: 10) {
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

                // 4. Launch & Emergency Controls
                HStack(spacing: 14) {
                    Button {
                        vm.startScan()
                    } label: {
                        Label("Start Authorized Security Scan", systemImage: "bolt.shield.fill")
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
                            Label(vm.isPaused ? "Resume Scan" : "Pause Scan", systemImage: vm.isPaused ? "play.fill" : "pause.fill")
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                        }
                        .buttonStyle(.bordered)

                        Button(role: .destructive) {
                            vm.emergencyStopScan()
                        } label: {
                            Label("EMERGENCY STOP", systemImage: "Octagon.fill")
                                .font(.headline)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.red)
                    }
                }

                // 5. Live Scan Telemetry Panel
                SectionCard(title: "Live Scan Progress & Telemetry", icon: "waveform.path.ecg.rectangle") {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Current Module: \(vm.liveProgress.currentModule)")
                                    .font(.headline)
                                    .foregroundStyle(.white)
                                Text("Status: \(vm.liveProgress.status)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 4) {
                                Text("Coverage: \(String(format: "%.0f%%", vm.liveProgress.coveragePercent)) (\(vm.liveProgress.checksCompleted)/\(vm.liveProgress.totalChecks) modules)")
                                    .font(.subheadline.weight(.semibold))
                                    .foregroundStyle(SentinelTheme.accentCyan)
                                Text("Elapsed: \(vm.liveProgress.elapsedSeconds)s • Est. Remaining: \(vm.liveProgress.estimatedRemainingSeconds)s")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }

                        ProgressView(value: vm.liveProgress.coveragePercent, total: 100.0)
                            .tint(SentinelTheme.accentCyan)

                        HStack(spacing: 24) {
                            Label("Endpoints Examined: \(vm.liveProgress.endpointsExamined)", systemImage: "globe")
                            Label("Checks Completed: \(vm.liveProgress.checksCompleted)", systemImage: "checkmark.circle")
                            Label("Findings Discovered: \(vm.liveProgress.findingsCount)", systemImage: "exclamationmark.shield")
                        }
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.white.opacity(0.85))

                        if !vm.liveFindings.isEmpty {
                            Divider().overlay(SentinelTheme.border)
                            Text("Live Finding Feed")
                                .font(.caption.weight(.bold))
                                .foregroundStyle(.secondary)
                            ForEach(vm.liveFindings.suffix(5)) { f in
                                HStack {
                                    SeverityBadge(severity: f.severity)
                                    StatusBadge(status: f.status)
                                    Text(f.title)
                                        .font(.caption.weight(.medium))
                                        .foregroundStyle(.white)
                                    Spacer()
                                    Text(f.affectedURL)
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }
            }
            .padding(24)
        }
        .background(SentinelTheme.bgPrimary)
    }
}
