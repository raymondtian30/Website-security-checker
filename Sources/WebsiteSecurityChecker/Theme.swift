import SwiftUI
import SentinelKit

public enum NavigationTab: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard"
    case scanConfig = "Scan Setup"
    case malwareScanner = "Malware & Safety"
    case findings = "Findings & AI Lab"
    case history = "History & Compare"
    case settings = "Settings & About"

    public var id: String { rawValue }

    public var icon: String {
        switch self {
        case .dashboard: return "shield.lefthalf.filled.badge.checkmark"
        case .scanConfig: return "slider.horizontal.below.square.and.square.filled"
        case .malwareScanner: return "ladybug.fill"
        case .findings: return "sparkle.magnifyingglass"
        case .history: return "clock.arrow.circlepath"
        case .settings: return "info.circle.fill"
        }
    }
}

public enum SentinelTheme {
    public static let bgPrimary = Color(red: 0.05, green: 0.07, blue: 0.11)
    public static let bgCard = Color(red: 0.09, green: 0.12, blue: 0.18)
    public static let bgElevated = Color(red: 0.13, green: 0.17, blue: 0.25)
    public static let border = Color.white.opacity(0.09)
    public static let accentCyan = Color(red: 0.22, green: 0.74, blue: 0.97)

    public static func severityColor(_ severity: SeverityLevel) -> Color {
        switch severity {
        case .critical: return Color(red: 0.95, green: 0.26, blue: 0.26)
        case .high: return Color(red: 0.98, green: 0.45, blue: 0.10)
        case .medium: return Color(red: 0.93, green: 0.72, blue: 0.05)
        case .low: return Color(red: 0.22, green: 0.74, blue: 0.97)
        case .informational: return Color(red: 0.58, green: 0.64, blue: 0.72)
        }
    }

    public static func gradeColor(_ score: Int) -> Color {
        switch score {
        case 90...100: return Color(red: 0.16, green: 0.80, blue: 0.42)
        case 80..<90: return Color(red: 0.22, green: 0.74, blue: 0.97)
        case 70..<80: return Color(red: 0.93, green: 0.72, blue: 0.05)
        case 60..<70: return Color(red: 0.98, green: 0.45, blue: 0.10)
        default: return Color(red: 0.95, green: 0.26, blue: 0.26)
        }
    }
}

/// Interactive `?` tooltip icon that displays an explanation when hovered over or clicked.
public struct HelpTooltip: View {
    public let title: String
    public let explanation: String
    @State private var isShowingPopover = false

    public init(_ title: String = "How This Works", explanation: String) {
        self.title = title
        self.explanation = explanation
    }

    public var body: some View {
        Image(systemName: "questionmark.circle.fill")
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(isShowingPopover ? SentinelTheme.accentCyan : Color.secondary.opacity(0.85))
            .help(explanation)
            .onHover { hovering in
                isShowingPopover = hovering
            }
            .onTapGesture {
                isShowingPopover.toggle()
            }
            .popover(isPresented: $isShowingPopover, arrowEdge: .top) {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 6) {
                        Image(systemName: "info.circle.fill")
                            .foregroundStyle(SentinelTheme.accentCyan)
                        Text(title)
                            .font(.caption.weight(.bold))
                            .foregroundStyle(.white)
                    }
                    Text(explanation)
                        .font(.caption)
                        .foregroundStyle(.white.opacity(0.9))
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(12)
                .frame(width: 280, alignment: .leading)
                .background(SentinelTheme.bgCard)
            }
    }
}

public struct SeverityBadge: View {
    public let severity: SeverityLevel
    public init(severity: SeverityLevel) { self.severity = severity }

    public var body: some View {
        Text(severity.rawValue.uppercased())
            .font(.system(size: 10, weight: .bold, design: .rounded))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(SentinelTheme.severityColor(severity).opacity(0.18))
            .foregroundStyle(SentinelTheme.severityColor(severity))
            .overlay(
                RoundedRectangle(cornerRadius: 5)
                    .stroke(SentinelTheme.severityColor(severity).opacity(0.42), lineWidth: 1)
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
            .font(.system(size: 10, weight: .semibold))
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
    let helpText: String?
    let content: Content

    public init(
        title: String? = nil,
        icon: String? = nil,
        helpText: String? = nil,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.icon = icon
        self.helpText = helpText
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
                    if let helpText {
                        HelpTooltip(title, explanation: helpText)
                    }
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
