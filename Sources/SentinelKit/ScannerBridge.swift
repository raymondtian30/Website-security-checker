import Foundation
import SentinelCore

private final class CallbackContext {
    let onProgress: (ScanProgressUpdate) -> Void
    let onFinding: (VulnerabilityFinding) -> Void

    init(
        onProgress: @escaping (ScanProgressUpdate) -> Void,
        onFinding: @escaping (VulnerabilityFinding) -> Void
    ) {
        self.onProgress = onProgress
        self.onFinding = onFinding
    }
}

private struct RawFindingDTO: Decodable {
    let id: String
    let rootCauseKey: String
    let title: String
    let category: String
    let owaspCategory: String
    let severity: String
    let confidence: String
    let status: String
    let cvssScore: Double
    let affectedURL: String
    let affectedParameter: String
    let evidence: String
    let technicalExplanation: String
    let impact: String
    let safeReproduction: String
    let remediation: String

    func toDomain() -> VulnerabilityFinding {
        VulnerabilityFinding(
            id: id,
            rootCauseKey: rootCauseKey,
            title: title,
            category: category,
            owaspCategory: owaspCategory,
            severity: SeverityLevel(rawValue: severity) ?? .informational,
            confidence: ConfidenceLevel(rawValue: confidence) ?? .medium,
            status: FindingStatus(rawValue: status) ?? .informational,
            cvssScore: cvssScore,
            affectedURL: affectedURL,
            affectedParameter: affectedParameter,
            evidence: evidence,
            technicalExplanation: technicalExplanation,
            impact: impact,
            safeReproduction: safeReproduction,
            remediation: remediation,
            isResolved: false,
            aiAnalysis: nil
        )
    }
}

public final class ScannerBridge: @unchecked Sendable {
    private let lock = NSLock()
    private var activeHandle: SentinelEngineHandle?

    public init() {}

    public static func validateScope(config: ScanConfiguration, candidateURL: String) -> ScopeCheckResult {
        guard let configData = try? JSONEncoder().encode(config),
              let configJSON = String(data: configData, encoding: .utf8) else {
            return ScopeCheckResult(allowed: false, reason: "Failed to encode configuration", resolvedIP: "")
        }

        return configJSON.withCString { cfgPtr in
            candidateURL.withCString { urlPtr in
                guard let rawPtr = sentinel_validate_url_scope(cfgPtr, urlPtr) else {
                    return ScopeCheckResult(allowed: false, reason: "Null bridge response", resolvedIP: "")
                }
                defer { sentinel_free_string(rawPtr) }
                let jsonStr = String(cString: rawPtr)
                if let data = jsonStr.data(using: .utf8),
                   let decoded = try? JSONDecoder().decode(ScopeCheckResult.self, from: data) {
                    return decoded
                }
                return ScopeCheckResult(allowed: false, reason: "Failed to decode scope check response", resolvedIP: "")
            }
        }
    }

    public static func redact(_ rawText: String) -> String {
        rawText.withCString { ptr in
            guard let outPtr = sentinel_redact_text(ptr) else { return rawText }
            defer { sentinel_free_string(outPtr) }
            return String(cString: outPtr)
        }
    }

    public func pause() {
        lock.lock()
        let h = activeHandle
        lock.unlock()
        if let h {
            sentinel_pause_scan(h)
        }
    }

    public func resume() {
        lock.lock()
        let h = activeHandle
        lock.unlock()
        if let h {
            sentinel_resume_scan(h)
        }
    }

    public func cancel() {
        lock.lock()
        let h = activeHandle
        lock.unlock()
        if let h {
            sentinel_cancel_scan(h)
        }
    }

    public func executeScan(
        config: ScanConfiguration,
        onProgress: @escaping @Sendable (ScanProgressUpdate) -> Void,
        onFinding: @escaping @Sendable (VulnerabilityFinding) -> Void
    ) async throws -> ScanRecord {
        let startTime = Date()
        let configData = try JSONEncoder().encode(config)
        guard let configJSON = String(data: configData, encoding: .utf8) else {
            throw NSError(domain: "ScannerBridge", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid scan configuration JSON."])
        }

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                guard let handle = sentinel_engine_create() else {
                    continuation.resume(throwing: NSError(domain: "ScannerBridge", code: 2, userInfo: [NSLocalizedDescriptionKey: "Unable to create C++ scanning engine."]))
                    return
                }

                self.lock.lock()
                self.activeHandle = handle
                self.lock.unlock()

                defer {
                    self.lock.lock()
                    self.activeHandle = nil
                    self.lock.unlock()
                    sentinel_engine_destroy(handle)
                }

                var collectedFindings: [VulnerabilityFinding] = []
                let findingsLock = NSLock()

                let ctx = CallbackContext(
                    onProgress: { prog in
                        onProgress(prog)
                    },
                    onFinding: { finding in
                        var enriched = finding
                        enriched.aiAnalysis = AISecurityAnalyst.generateDeterministicAnalysis(for: enriched, allFindings: collectedFindings)
                        findingsLock.lock()
                        collectedFindings.append(enriched)
                        findingsLock.unlock()
                        onFinding(enriched)
                    }
                )

                let unmanagedCtx = Unmanaged.passRetained(ctx)
                defer { unmanagedCtx.release() }

                let progressCB: SentinelProgressCallback = { jsonPtr, userData in
                    guard let jsonPtr, let userData else { return }
                    let context = Unmanaged<CallbackContext>.fromOpaque(userData).takeUnretainedValue()
                    let jsonStr = String(cString: jsonPtr)
                    if let data = jsonStr.data(using: .utf8),
                       let prog = try? JSONDecoder().decode(ScanProgressUpdate.self, from: data) {
                        context.onProgress(prog)
                    }
                }

                let findingCB: SentinelFindingCallback = { jsonPtr, userData in
                    guard let jsonPtr, let userData else { return }
                    let context = Unmanaged<CallbackContext>.fromOpaque(userData).takeUnretainedValue()
                    let jsonStr = String(cString: jsonPtr)
                    if let data = jsonStr.data(using: .utf8),
                       let dto = try? JSONDecoder().decode(RawFindingDTO.self, from: data) {
                        context.onFinding(dto.toDomain())
                    }
                }

                let summaryStr: String = configJSON.withCString { cfgPtr in
                    guard let resPtr = sentinel_run_scan(handle, cfgPtr, progressCB, findingCB, unmanagedCtx.toOpaque()) else {
                        return "{\"success\":false,\"status\":\"Failed\",\"error\":\"Null engine summary\",\"endpointsExamined\":0,\"checksCompleted\":0,\"totalChecks\":10,\"coveragePercent\":0.0}"
                    }
                    defer { sentinel_free_string(resPtr) }
                    return String(cString: resPtr)
                }

                guard let summaryData = summaryStr.data(using: .utf8),
                      let summary = try? JSONDecoder().decode(ScanSummaryResponse.self, from: summaryData) else {
                    continuation.resume(throwing: NSError(domain: "ScannerBridge", code: 3, userInfo: [NSLocalizedDescriptionKey: "Failed to parse C++ engine scan summary."]))
                    return
                }

                if !summary.success && summary.status == "Failed" {
                    continuation.resume(throwing: NSError(domain: "ScannerBridge", code: 4, userInfo: [NSLocalizedDescriptionKey: summary.error.isEmpty ? "Scan failed." : summary.error]))
                    return
                }

                // Re-enrich findings with full scan context so related findings are cross-referenced
                let finalFindings = collectedFindings.map { item -> VulnerabilityFinding in
                    var copy = item
                    copy.aiAnalysis = AISecurityAnalyst.generateDeterministicAnalysis(for: copy, allFindings: collectedFindings)
                    return copy
                }.sorted { a, b in
                    if a.severity != b.severity { return a.severity > b.severity }
                    return a.cvssScore > b.cvssScore
                }

                let scoreBreakdown = SecurityScorer.calculateScore(
                    findings: finalFindings,
                    completedChecks: summary.checksCompleted,
                    totalChecks: summary.totalChecks
                )

                let duration = max(1, Int(Date().timeIntervalSince(startTime)))
                let record = ScanRecord(
                    targetURL: config.targetURL,
                    targetDomain: config.targetDomain,
                    configuration: config,
                    scoreBreakdown: scoreBreakdown,
                    findings: finalFindings,
                    status: summary.status,
                    endpointsExamined: summary.endpointsExamined,
                    durationSeconds: duration
                )

                continuation.resume(returning: record)
            }
        }
    }
}
