import Foundation
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import SentinelKit

public enum ReportFormat: String, CaseIterable {
    case pdf = "PDF"
    case html = "HTML"
    case json = "JSON"
}

@MainActor
public final class AppViewModel: ObservableObject {
    @Published public var selectedTab: NavigationTab = .dashboard
    @Published public var scanConfig = ScanConfiguration()
    @Published public var allowedSubdomainsInput: String = ""
    @Published public var excludedPathsInput: String = "/logout, /signout, /delete"

    @Published public var isScanning: Bool = false
    @Published public var isPaused: Bool = false
    @Published public var liveProgress = ScanProgressUpdate()
    @Published public var liveFindings: [VulnerabilityFinding] = []
    @Published public var statusBannerMessage: String?
    @Published public var errorMessage: String?

    @Published public var scanHistory: [ScanRecord] = []
    @Published public var activeScan: ScanRecord?
    @Published public var selectedFinding: VulnerabilityFinding?
    @Published public var auditLogs: [AuditLogEntry] = []

    // Findings filter state
    @Published public var severityFilter: SeverityLevel? = nil
    @Published public var categoryFilter: String = "All"
    @Published public var statusFilter: FindingStatus? = nil
    @Published public var hideResolved: Bool = false
    @Published public var searchQuery: String = ""
    @Published public var sortByConfidence: Bool = false

    // Scan comparison state
    @Published public var comparisonBaselineID: UUID?
    @Published public var comparisonCurrentID: UUID?

    // AI Settings state
    @Published public var selectedAIProvider: AIProvider = .openAI
    @Published public var aiModelInput: String = AIProvider.openAI.defaultModel
    @Published public var apiKeyInput: String = ""
    @Published public var hasSavedAPIKey: Bool = false
    @Published public var isRequestingAI: Bool = false
    @Published public var aiSettingsStatus: String?

    public let db = DatabaseManager()
    private let scannerBridge = ScannerBridge()

    public init() {
        reloadPersistence()
        refreshKeychainStatus()
    }

    public func reloadPersistence() {
        scanHistory = db.loadAllScans()
        if activeScan == nil {
            activeScan = scanHistory.first
        } else if let currentID = activeScan?.id,
                  let updated = scanHistory.first(where: { $0.id == currentID }) {
            activeScan = updated
        }
        if selectedFinding == nil {
            selectedFinding = activeScan?.findings.first
        }
        if scanHistory.count >= 2 {
            if comparisonCurrentID == nil { comparisonCurrentID = scanHistory[0].id }
            if comparisonBaselineID == nil { comparisonBaselineID = scanHistory[1].id }
        }
        auditLogs = db.loadAuditLogs()
    }

    public func syncDomainFromTargetURL() {
        let trimmed = scanConfig.targetURL.trimmingCharacters(in: .whitespacesAndNewlines)
        if let url = URL(string: trimmed), let host = url.host, !host.isEmpty {
            scanConfig.targetDomain = host.lowercased()
        }
    }

    public func startScan() {
        errorMessage = nil
        statusBannerMessage = nil
        syncDomainFromTargetURL()

        scanConfig.allowedSubdomains = allowedSubdomainsInput
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        scanConfig.excludedPaths = excludedPathsInput
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        guard scanConfig.authorized else {
            errorMessage = "You must confirm ownership or explicit written authorization before starting a scan."
            db.logAuditEvent(AuditLogEntry(
                action: "SCAN_BLOCKED_UNAUTHORIZED",
                targetDomain: scanConfig.targetDomain,
                authorizedConfirmed: false,
                details: "Attempted scan on \(scanConfig.targetURL) without authorization confirmation."
            ))
            auditLogs = db.loadAuditLogs()
            return
        }

        // Pre-validate scope via C++ ScopeGuard
        let scopeCheck = ScannerBridge.validateScope(config: scanConfig, candidateURL: scanConfig.targetURL)
        if !scopeCheck.allowed {
            errorMessage = "Scope & Safety Protection Blocked Scan: \(scopeCheck.reason)"
            db.logAuditEvent(AuditLogEntry(
                action: "SCAN_BLOCKED_SCOPE_GUARD",
                targetDomain: scanConfig.targetDomain,
                authorizedConfirmed: true,
                details: "Target \(scanConfig.targetURL) rejected: \(scopeCheck.reason)"
            ))
            auditLogs = db.loadAuditLogs()
            return
        }

        isScanning = true
        isPaused = false
        liveFindings = []
        liveProgress = ScanProgressUpdate(
            currentModule: "Initializing Scope Guard & Engine...",
            status: "Running",
            endpointsExamined: 0,
            checksCompleted: 0,
            totalChecks: max(1, scanConfig.enabledCategories.count),
            findingsCount: 0,
            coveragePercent: 0
        )

        db.logAuditEvent(AuditLogEntry(
            action: "SCAN_STARTED",
            targetDomain: scanConfig.targetDomain,
            authorizedConfirmed: true,
            details: "URL: \(scanConfig.targetURL) | Resolved IP: \(scopeCheck.resolvedIP) | Intensity: \(scanConfig.intensity) | Rate: \(scanConfig.maxRequestsPerSecond) RPS"
        ))
        auditLogs = db.loadAuditLogs()

        let cfg = scanConfig
        Task {
            do {
                let record = try await scannerBridge.executeScan(
                    config: cfg,
                    onProgress: { [weak self] prog in
                        Task { @MainActor [weak self] in
                            self?.liveProgress = prog
                        }
                    },
                    onFinding: { [weak self] finding in
                        Task { @MainActor [weak self] in
                            self?.liveFindings.append(finding)
                        }
                    }
                )

                try? db.saveScan(record)
                db.logAuditEvent(AuditLogEntry(
                    action: "SCAN_\(record.status.uppercased())",
                    targetDomain: record.targetDomain,
                    authorizedConfirmed: true,
                    details: "Score: \(record.scoreBreakdown.overallScore)/100 (\(record.scoreBreakdown.letterGrade)) | Coverage: \(Int(record.scoreBreakdown.coveragePercent))% | Findings: \(record.findings.count)"
                ))

                isScanning = false
                isPaused = false
                activeScan = record
                selectedFinding = record.findings.first
                reloadPersistence()
                statusBannerMessage = "Assessment completed: Score \(record.scoreBreakdown.overallScore)/100 (Grade \(record.scoreBreakdown.letterGrade))"
            } catch {
                isScanning = false
                isPaused = false
                errorMessage = error.localizedDescription
                db.logAuditEvent(AuditLogEntry(
                    action: "SCAN_ERROR",
                    targetDomain: cfg.targetDomain,
                    authorizedConfirmed: cfg.authorized,
                    details: error.localizedDescription
                ))
                auditLogs = db.loadAuditLogs()
            }
        }
    }

    public func togglePauseScan() {
        guard isScanning else { return }
        if isPaused {
            scannerBridge.resume()
            isPaused = false
            liveProgress.status = "Running"
        } else {
            scannerBridge.pause()
            isPaused = true
            liveProgress.status = "Paused"
        }
    }

    public func emergencyStopScan() {
        guard isScanning else { return }
        scannerBridge.cancel()
        isPaused = false
        liveProgress.status = "Cancelling..."
        db.logAuditEvent(AuditLogEntry(
            action: "EMERGENCY_STOP_TRIGGERED",
            targetDomain: scanConfig.targetDomain,
            authorizedConfirmed: scanConfig.authorized,
            details: "User triggered Emergency Stop on active scan of \(scanConfig.targetURL)."
        ))
        auditLogs = db.loadAuditLogs()
    }

    public func toggleResolved(for finding: VulnerabilityFinding) {
        guard let scanID = activeScan?.id else { return }
        if let updated = try? db.toggleFindingResolved(scanID: scanID, findingID: finding.id) {
            activeScan = updated
            if let updatedFinding = updated.findings.first(where: { $0.id == finding.id }) {
                selectedFinding = updatedFinding
            }
            reloadPersistence()
        }
    }

    public func investigate(_ finding: VulnerabilityFinding) {
        selectedFinding = finding
        selectedTab = .investigation
    }

    public func runEnhancedAIAnalysis() {
        guard let finding = selectedFinding, let scan = activeScan else { return }
        isRequestingAI = true
        let provider = selectedAIProvider
        let model = aiModelInput
        let allFindings = scan.findings

        Task {
            do {
                let enhanced = try await AISecurityAnalyst.requestEnhancedLLMAnalysis(
                    for: finding,
                    allFindings: allFindings,
                    provider: provider,
                    customModel: model
                )
                var updatedScan = scan
                if let idx = updatedScan.findings.firstIndex(where: { $0.id == finding.id }) {
                    updatedScan.findings[idx].aiAnalysis = enhanced
                    try? db.saveScan(updatedScan)
                    activeScan = updatedScan
                    selectedFinding = updatedScan.findings[idx]
                    reloadPersistence()
                }
            } catch {
                errorMessage = "Enhanced AI request failed: \(error.localizedDescription)"
            }
            isRequestingAI = false
        }
    }

    public func refreshKeychainStatus() {
        if let existing = KeychainHelper.loadKey(for: selectedAIProvider), !existing.isEmpty {
            hasSavedAPIKey = true
        } else {
            hasSavedAPIKey = false
        }
        aiModelInput = selectedAIProvider.defaultModel
    }

    public func saveAPIKeyToKeychain() {
        let trimmed = apiKeyInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            aiSettingsStatus = "Please enter a non-empty API key."
            return
        }
        if KeychainHelper.saveKey(trimmed, for: selectedAIProvider) {
            apiKeyInput = ""
            hasSavedAPIKey = true
            aiSettingsStatus = "API key saved securely in macOS Keychain for \(selectedAIProvider.rawValue)."
            db.logAuditEvent(AuditLogEntry(
                action: "AI_API_KEY_CONFIGURED",
                targetDomain: "System Keychain",
                authorizedConfirmed: true,
                details: "Saved API key for provider \(selectedAIProvider.rawValue) in macOS Keychain."
            ))
            auditLogs = db.loadAuditLogs()
        } else {
            aiSettingsStatus = "Failed to save API key to macOS Keychain."
        }
    }

    public func removeAPIKeyFromKeychain() {
        KeychainHelper.deleteKey(for: selectedAIProvider)
        hasSavedAPIKey = false
        aiSettingsStatus = "Removed stored API key for \(selectedAIProvider.rawValue)."
    }

    public var filteredFindings: [VulnerabilityFinding] {
        guard let scan = activeScan else { return [] }
        var list = scan.findings

        if let sev = severityFilter {
            list = list.filter { $0.severity == sev }
        }
        if categoryFilter != "All" {
            list = list.filter { $0.category == categoryFilter }
        }
        if let st = statusFilter {
            list = list.filter { $0.status == st }
        }
        if hideResolved {
            list = list.filter { !$0.isResolved }
        }
        let q = searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !q.isEmpty {
            list = list.filter {
                $0.title.lowercased().contains(q) ||
                $0.affectedURL.lowercased().contains(q) ||
                $0.affectedParameter.lowercased().contains(q) ||
                $0.category.lowercased().contains(q) ||
                $0.owaspCategory.lowercased().contains(q)
            }
        }
        if sortByConfidence {
            list.sort { a, b in
                if a.confidence != b.confidence { return a.confidence > b.confidence }
                return a.severity > b.severity
            }
        } else {
            list.sort { a, b in
                if a.severity != b.severity { return a.severity > b.severity }
                return a.cvssScore > b.cvssScore
            }
        }
        return list
    }

    public func exportReport(for scan: ScanRecord, format: ReportFormat) {
        let savePanel = NSSavePanel()
        savePanel.canCreateDirectories = true
        let safeDomain = scan.targetDomain.replacingOccurrences(of: ":", with: "_")
        switch format {
        case .pdf:
            savePanel.nameFieldStringValue = "Sentinel-Report-\(safeDomain).pdf"
            savePanel.allowedContentTypes = [.pdf]
        case .html:
            savePanel.nameFieldStringValue = "Sentinel-Report-\(safeDomain).html"
            savePanel.allowedContentTypes = [.html]
        case .json:
            savePanel.nameFieldStringValue = "Sentinel-Report-\(safeDomain).json"
            savePanel.allowedContentTypes = [.json]
        }

        if savePanel.runModal() == .OK, let url = savePanel.url {
            do {
                switch format {
                case .pdf:
                    let data = ReportGenerator.generatePDFReport(for: scan)
                    try data.write(to: url)
                case .html:
                    let html = ReportGenerator.generateHTMLReport(for: scan)
                    try html.write(to: url, atomically: true, encoding: .utf8)
                case .json:
                    let data = try ReportGenerator.generateJSONReport(for: scan)
                    try data.write(to: url)
                }
                statusBannerMessage = "Exported \(format.rawValue) report to \(url.lastPathComponent)"
            } catch {
                errorMessage = "Failed to export report: \(error.localizedDescription)"
            }
        }
    }
}
