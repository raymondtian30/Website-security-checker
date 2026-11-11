import SwiftUI
import SentinelKit

public enum NavigationTab: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard"
    case scanConfig = "Scan & Monitor"
    case malwareScanner = "Malware & Safety"
    case findings = "Findings"
    case investigation = "AI Investigation"
    case history = "History & Compare"
    case settings = "Settings & Audit Log"

    public var id: String { rawValue }

    public var icon: String {
        switch self {
        case .dashboard: return "shield.lefthalf.filled.badge.checkmark"
        case .scanConfig: return "dot.radiowaves.left.and.right"
        case .malwareScanner: return "ladybug.fill"
        case .findings: return "exclamationmark.triangle.fill"
        case .investigation: return "brain.head.profile"
        case .history: return "clock.arrow.circlepath"
        case .settings: return "gearshape.2.fill"
        }
    }
}

public enum SentinelTheme {
    public static let bgPrimary = Color(red: 0.06, green: 0.08, blue: 0.13)
    public static let bgCard = Color(red: 0.10, green: 0.13, blue: 0.19)
    public static let bgElevated = Color(red: 0.14, green: 0.18, blue: 0.26)
    public static let border = Color.white.opacity(0.10)
    public static let accentCyan = Color(red: 0.22, green: 0.74, blue: 0.97)

    public static func severityColor(_ severity: SeverityLevel) -> Color {
        switch severity {
        case .critical: return Color(red: 0.94, green: 0.27, blue: 0.27)
        case .high: return Color(red: 0.98, green: 0.45, blue: 0.09)
        case .medium: return Color(red: 0.92, green: 0.70, blue: 0.03)
        case .low: return Color(red: 0.22, green: 0.74, blue: 0.97)
        case .informational: return Color(red: 0.58, green: 0.64, blue: 0.72)
        }
    }

    public static func gradeColor(_ score: Int) -> Color {
        switch score {
        case 90...100: return Color(red: 0.13, green: 0.77, blue: 0.37)
        case 80..<90: return Color(red: 0.22, green: 0.74, blue: 0.97)
        case 70..<80: return Color(red: 0.92, green: 0.70, blue: 0.03)
        case 60..<70: return Color(red: 0.98, green: 0.45, blue: 0.09)
        default: return Color(red: 0.94, green: 0.27, blue: 0.27)
        }
    }
}

public struct SeverityBadge: View {
    public let severity: SeverityLevel
    public init(severity: SeverityLevel) { self.severity = severity }

    public var body: some View {
        Text(severity.rawValue.uppercased())
            .font(.system(size: 10.5, weight: .bold, design: .rounded))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(SentinelTheme.severityColor(severity).opacity(0.20))
            .foregroundStyle(SentinelTheme.severityColor(severity))
            .overlay(
                RoundedRectangle(cornerRadius: 5)
                    .stroke(SentinelTheme.severityColor(severity).opacity(0.45), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: 5))
    }
}

public struct StatusBadge: View {
    public let status: FindingStatus
    public init(status: FindingStatus) { self.status = status }

    private var color: Color {
        switch status {
        case .verified: return Color.green
        case .suspected: return Color.orange
        case .manualReviewRequired: return Color.purple
        case .informational: return Color.gray
        case .incomplete: return Color.secondary
        }
    }

    public var body: some View {
        Text(status.displayLabel)
            .font(.system(size: 10.5, weight: .semibold))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(color.opacity(0.16))
            .foregroundStyle(color)
            .clipShape(RoundedRectangle(cornerRadius: 5))
    }
}

public struct SectionCard<Content: View>: View {
    let title: String?
    let icon: String?
    let content: Content

    public init(title: String? = nil, icon: String? = nil, @ViewBuilder content: () -> Content) {
        self.title = title
        self.icon = icon
        self.content = content()
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let title {
                HStack(spacing: 8) {
                    if let icon {
                        Image(systemName: icon)
                            .foregroundStyle(SentinelTheme.accentCyan)
                    }
                    Text(title)
                        .font(.headline)
                        .foregroundStyle(.white)
                }
            }
            content
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(SentinelTheme.bgCard)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(SentinelTheme.border, lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}
