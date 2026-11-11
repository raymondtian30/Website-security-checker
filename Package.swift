// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "WebsiteSecurityChecker",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "SentinelKit", targets: ["SentinelKit"]),
        .executable(name: "WebsiteSecurityChecker", targets: ["WebsiteSecurityChecker"]),
        .executable(name: "SentinelTestRunner", targets: ["SentinelTestRunner"])
    ],
    targets: [
        .target(
            name: "SentinelCore",
            path: "Sources/SentinelCore",
            publicHeadersPath: "include",
            cxxSettings: [
                .headerSearchPath("src"),
                .unsafeFlags(["-std=c++17"])
            ],
            linkerSettings: [
                .linkedLibrary("curl")
            ]
        ),
        .target(
            name: "SentinelKit",
            dependencies: ["SentinelCore"],
            path: "Sources/SentinelKit",
            linkerSettings: [
                .linkedLibrary("sqlite3"),
                .linkedFramework("Security"),
                .linkedFramework("PDFKit"),
                .linkedFramework("AppKit")
            ]
        ),
        .executableTarget(
            name: "WebsiteSecurityChecker",
            dependencies: ["SentinelKit"],
            path: "Sources/WebsiteSecurityChecker",
            linkerSettings: [
                .linkedFramework("SwiftUI"),
                .linkedFramework("Charts"),
                .linkedFramework("AppKit")
            ]
        ),
        .executableTarget(
            name: "SentinelTestRunner",
            dependencies: ["SentinelKit", "SentinelCore"],
            path: "Tests/SentinelTests",
            linkerSettings: [
                .linkedFramework("Network")
            ]
        )
    ],
    cxxLanguageStandard: .cxx17
)
