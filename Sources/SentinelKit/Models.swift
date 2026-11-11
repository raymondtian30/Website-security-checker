import Foundation

public enum SeverityLevel: String, Codable, CaseIterable, Comparable, Sendable {
    case critical = "Critical"
    case high = "High"
    case medium = "Medium"
    case low = "Low"
    case informational = "Informational"

    public var rank: Int {
        switch self {
        case .critical: return 5
        case .high: return 4
        case .medium: return 3
        case .low: return 2
        case .informational: return 1
        }
    }

    public static func < (lhs: SeverityLevel, rhs: SeverityLevel) -> Bool {
        lhs.rank < rhs.rank
    }
}

public enum ConfidenceLevel: String, Codable, CaseIterable, Comparable, Sendable {
    case high = "High"
    case medium = "Medium"
    case low = "Low"

    public var rank: Int {
        switch self {
        case .high: return 3
        case .medium: return 2
        case .low: return 1
        }
    }

    public static func < (lhs: ConfidenceLevel, rhs: ConfidenceLevel) -> Bool {
        lhs.rank < rhs.rank
    }
}

public enum FindingStatus: String, Codable, CaseIterable, Sendable {
    case verified = "Verified"
    case suspected = "Suspected"
    case informational = "Informational"
    case manualReviewRequired = "ManualReviewRequired"
    case incomplete = "Incomplete"

    public var displayLabel: String {
        switch self {
        case .verified: return "Verified"
        case .suspected: return "Suspected"
        case .informational: return "Informational"
        case .manualReviewRequired: return "Needs Manual Review"
        case .incomplete: return "Incomplete Check"
        }
    }
}

public enum ScanIntensity: String, Codable, CaseIterable, Sendable {
    case passive = "Passive"
    case standard = "Standard"
    case thorough = "Thorough"

    public var description: String {
        switch self {
        case .passive:
            return "Safe header, cookie, TLS, and static HTML inspection on primary pages only."
        case .standard:
            return "Balanced in-scope crawling and non-destructive indicator verification (Recommended)."
        case .thorough:
            return "Deeper endpoint discovery and comprehensive parameter indicator analysis."
        }
    }
}

public enum ScanCategory: String, Codable, CaseIterable, Identifiable, Sendable {
    case tls = "TLS / HTTPS"
    case headers = "Security Headers"
    case authSession = "Authentication & Session"
    case csrf = "CSRF"
    case serverSecurity = "Server-Side Security"
    case infoDisclosure = "Information Disclosure"
    case apiSecurity = "API Security"
    case sqli = "SQL Injection"
    case xss = "Cross-Site Scripting (XSS)"
    case owasp = "OWASP Top 10"
    case malware = "Malware & Visitor Safety"

    public var id: String { rawValue }
}

public struct VisitorSafetyEvaluation: Codable, Equatable, Sendable {
    public var safetyScore: Int // 1 to 100
    public var safetyGrade: String // F to A+
    public var isSafeToVisit: Bool
    public var verdictLabel: String
    public var verdictDescription: String
    public var detectedMalware: [VulnerabilityFinding]
    public var checkedCategories: [String]

    public init(
        safetyScore: Int,
        safetyGrade: String,
        isSafeToVisit: Bool,
        verdictLabel: String,
        verdictDescription: String,
        detectedMalware: [VulnerabilityFinding],
        checkedCategories: [String] = [
            "Magecart & Payment Card Web Skimmers",
            "Browser Cryptojackers & Coin Miners",
            "Obfuscated JavaScript Eval Droppers",
            "Hidden Exploit Kit & TDS Iframes",
            "Drive-By Executable Malware Downloads",
            "Webshells & Server Backdoors",
            "Cleartext Credential & Phishing Harvesters"
        ]
    ) {
        self.safetyScore = max(1, min(100, safetyScore))
        self.safetyGrade = safetyGrade
        self.isSafeToVisit = isSafeToVisit
        self.verdictLabel = verdictLabel
        self.verdictDescription = verdictDescription
        self.detectedMalware = detectedMalware
        self.checkedCategories = checkedCategories
    }
}

public struct ScanConfiguration: Codable, Equatable, Sendable {
    public var targetURL: String
    public var targetDomain: String
    public var authorized: Bool
    public var includeSubdomains: Bool
    public var allowedSubdomains: [String]
    public var excludedPaths: [String]
    public var enabledCategories: [String]
    public var intensity: String
    public var maxDurationSeconds: Int
    public var maxRequestsPerSecond: Int
    public var requestTimeoutSeconds: Int
    public var maxRedirects: Int
    public var maxCrawlPages: Int
    public var allowLocalTestbench: Bool

    public init(
        targetURL: String = "https://example.com",
        targetDomain: String = "example.com",
        authorized: Bool = false,
        includeSubdomains: Bool = false,
        allowedSubdomains: [String] = [],
        excludedPaths: [String] = ["/logout", "/signout", "/delete"],
        enabledCategories: [String] = ScanCategory.allCases.map(\.rawValue),
        intensity: String = ScanIntensity.standard.rawValue,
        maxDurationSeconds: Int = 120,
        maxRequestsPerSecond: Int = 8,
        requestTimeoutSeconds: Int = 8,
        maxRedirects: Int = 5,
        maxCrawlPages: Int = 20,
        allowLocalTestbench: Bool = false
    ) {
        self.targetURL = targetURL
        self.targetDomain = targetDomain
        self.authorized = authorized
        self.includeSubdomains = includeSubdomains
        self.allowedSubdomains = allowedSubdomains
        self.excludedPaths = excludedPaths
        self.enabledCategories = enabledCategories
        self.intensity = intensity
        self.maxDurationSeconds = maxDurationSeconds
        self.maxRequestsPerSecond = maxRequestsPerSecond
        self.requestTimeoutSeconds = requestTimeoutSeconds
        self.maxRedirects = maxRedirects
        self.maxCrawlPages = maxCrawlPages
        self.allowLocalTestbench = allowLocalTestbench
    }
}

public struct AIAnalysisResult: Codable, Equatable, Hashable, Sendable {
    public var plainLanguageSummary: String
    public var relatedFindingsAnalysis: String
    public var conceptualAbuseScenario: String
    public var falsePositiveAssessment: String
    public var controlledValidationProcedure: String
    public var secureCodePattern: String
    public var remediationPriority: String
    public var testingLimitations: String
    public var generatedByModel: String
    public var generatedAt: Date

    public init(
        plainLanguageSummary: String,
        relatedFindingsAnalysis: String,
        conceptualAbuseScenario: String,
        falsePositiveAssessment: String,
        controlledValidationProcedure: String,
        secureCodePattern: String,
        remediationPriority: String,
        testingLimitations: String,
        generatedByModel: String,
        generatedAt: Date = Date()
    ) {
        self.plainLanguageSummary = plainLanguageSummary
        self.relatedFindingsAnalysis = relatedFindingsAnalysis
        self.conceptualAbuseScenario = conceptualAbuseScenario
        self.falsePositiveAssessment = falsePositiveAssessment
        self.controlledValidationProcedure = controlledValidationProcedure
        self.secureCodePattern = secureCodePattern
        self.remediationPriority = remediationPriority
        self.testingLimitations = testingLimitations
        self.generatedByModel = generatedByModel
        self.generatedAt = generatedAt
    }
}

public struct VulnerabilityFinding: Codable, Identifiable, Equatable, Hashable, Sendable {
    public var id: String
    public var rootCauseKey: String
    public var title: String
    public var category: String
    public var owaspCategory: String
    public var severity: SeverityLevel
    public var confidence: ConfidenceLevel
    public var status: FindingStatus
    public var cvssScore: Double
    public var affectedURL: String
    public var affectedParameter: String
    public var evidence: String
    public var technicalExplanation: String
    public var impact: String
    public var safeReproduction: String
    public var remediation: String
    public var isResolved: Bool
    public var aiAnalysis: AIAnalysisResult?

    public init(
        id: String,
        rootCauseKey: String,
        title: String,
        category: String,
        owaspCategory: String,
        severity: SeverityLevel,
        confidence: ConfidenceLevel,
        status: FindingStatus,
        cvssScore: Double,
        affectedURL: String,
        affectedParameter: String,
        evidence: String,
        technicalExplanation: String,
        impact: String,
        safeReproduction: String,
        remediation: String,
        isResolved: Bool = false,
        aiAnalysis: AIAnalysisResult? = nil
    ) {
        self.id = id
        self.rootCauseKey = rootCauseKey
        self.title = title
        self.category = category
        self.owaspCategory = owaspCategory
        self.severity = severity
        self.confidence = confidence
        self.status = status
        self.cvssScore = cvssScore
        self.affectedURL = affectedURL
        self.affectedParameter = affectedParameter
        self.evidence = evidence
        self.technicalExplanation = technicalExplanation
        self.impact = impact
        self.safeReproduction = safeReproduction
        self.remediation = remediation
        self.isResolved = isResolved
        self.aiAnalysis = aiAnalysis
    }
}

public struct ScanProgressUpdate: Codable, Equatable, Sendable {
    public var currentModule: String
    public var status: String
    public var endpointsExamined: Int
    public var checksCompleted: Int
    public var totalChecks: Int
    public var findingsCount: Int
    public var coveragePercent: Double
    public var elapsedSeconds: Int
    public var estimatedRemainingSeconds: Int

    public init(
        currentModule: String = "Idle",
        status: String = "Idle",
        endpointsExamined: Int = 0,
        checksCompleted: Int = 0,
        totalChecks: Int = 10,
        findingsCount: Int = 0,
        coveragePercent: Double = 0.0,
        elapsedSeconds: Int = 0,
        estimatedRemainingSeconds: Int = 0
    ) {
        self.currentModule = currentModule
        self.status = status
        self.endpointsExamined = endpointsExamined
        self.checksCompleted = checksCompleted
        self.totalChecks = totalChecks
        self.findingsCount = findingsCount
        self.coveragePercent = coveragePercent
        self.elapsedSeconds = elapsedSeconds
        self.estimatedRemainingSeconds = estimatedRemainingSeconds
    }
}

public struct ScanSummaryResponse: Codable, Equatable, Sendable {
    public var success: Bool
    public var status: String
    public var error: String
    public var endpointsExamined: Int
    public var checksCompleted: Int
    public var totalChecks: Int
    public var findingsCount: Int?
    public var coveragePercent: Double
}

public struct ScopeCheckResult: Codable, Equatable, Sendable {
    public var allowed: Bool
    public var reason: String
    public var resolvedIP: String
}

public struct SecurityScoreBreakdown: Codable, Equatable, Sendable {
    public var overallScore: Int
    public var letterGrade: String
    public var postureMeaning: String
    public var coveragePercent: Double
    public var criticalCount: Int
    public var highCount: Int
    public var mediumCount: Int
    public var lowCount: Int
    public var infoCount: Int
    public var verifiedCount: Int
    public var suspectedCount: Int
    public var manualReviewCount: Int
    public var incompleteCount: Int
    public var deduplicatedRootCauses: Int
    public var scoringFactors: [String]
    public var algorithmExplanation: String
}

public struct ScanRecord: Codable, Identifiable, Equatable, Sendable {
    public var id: UUID
    public var timestamp: Date
    public var targetURL: String
    public var targetDomain: String
    public var configuration: ScanConfiguration
    public var scoreBreakdown: SecurityScoreBreakdown
    public var findings: [VulnerabilityFinding]
    public var status: String
    public var endpointsExamined: Int
    public var durationSeconds: Int

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        targetURL: String,
        targetDomain: String,
        configuration: ScanConfiguration,
        scoreBreakdown: SecurityScoreBreakdown,
        findings: [VulnerabilityFinding],
        status: String,
        endpointsExamined: Int,
        durationSeconds: Int
    ) {
        self.id = id
        self.timestamp = timestamp
        self.targetURL = targetURL
        self.targetDomain = targetDomain
        self.configuration = configuration
        self.scoreBreakdown = scoreBreakdown
        self.findings = findings
        self.status = status
        self.endpointsExamined = endpointsExamined
        self.durationSeconds = durationSeconds
    }
}

public struct ScanComparisonResult: Equatable, Sendable {
    public var baselineScan: ScanRecord
    public var currentScan: ScanRecord
    public var scoreDelta: Int
    public var coverageDelta: Double
    public var newFindings: [VulnerabilityFinding]
    public var resolvedFindings: [VulnerabilityFinding]
    public var persistingFindings: [VulnerabilityFinding]
}

public struct AuditLogEntry: Codable, Identifiable, Equatable, Sendable {
    public var id: UUID
    public var timestamp: Date
    public var action: String
    public var targetDomain: String
    public var authorizedConfirmed: Bool
    public var details: String

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        action: String,
        targetDomain: String,
        authorizedConfirmed: Bool,
        details: String
    ) {
        self.id = id
        self.timestamp = timestamp
        self.action = action
        self.targetDomain = targetDomain
        self.authorizedConfirmed = authorizedConfirmed
        self.details = details
    }
}
