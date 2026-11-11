#!/usr/bin/env zsh
set -euo pipefail

APP_EXEC="WebsiteSecurityChecker"
APP_NAME="Sentinal"
BUNDLE_ID="com.sentinal.securityauditor"
ROOT_DIR="$(pwd)"
APP_BUNDLE="${ROOT_DIR}/${APP_NAME}.app"

echo "==> Building ${APP_NAME} (Release configuration)..."
swift build -c release --product "${APP_EXEC}"

BIN_PATH="$(swift build -c release --show-bin-path)/${APP_EXEC}"

echo "==> Creating macOS Application Bundle at ${APP_BUNDLE}..."
rm -rf "${APP_BUNDLE}" "${ROOT_DIR}/WebsiteSecurityChecker.app"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

cp "${BIN_PATH}" "${APP_BUNDLE}/Contents/MacOS/${APP_NAME}"
chmod +x "${APP_BUNDLE}/Contents/MacOS/${APP_NAME}"

# Generate a crisp macOS AppIcon.icns using Swift CoreGraphics + iconutil
ICONSET_DIR="$(mktemp -d)/AppIcon.iconset"
mkdir -p "${ICONSET_DIR}"

swift - "${ICONSET_DIR}" <<'SWIFT_ICON'
import AppKit
import CoreGraphics

let args = CommandLine.arguments
let outDir = args[1]

func renderIcon(size: Int, filename: String) {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: size,
        pixelsHigh: size,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    )!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let ctx = NSGraphicsContext.current!.cgContext
    let s = CGFloat(size)

    // Rounded rect dark background
    let rect = CGRect(x: s * 0.06, y: s * 0.06, width: s * 0.88, height: s * 0.88)
    let bgPath = CGPath(roundedRect: rect, cornerWidth: s * 0.20, cornerHeight: s * 0.20, transform: nil)
    ctx.addPath(bgPath)
    ctx.setFillColor(CGColor(red: 0.06, green: 0.09, blue: 0.16, alpha: 1.0))
    ctx.fillPath()

    // Cyan border
    ctx.addPath(bgPath)
    ctx.setStrokeColor(CGColor(red: 0.22, green: 0.74, blue: 0.97, alpha: 0.85))
    ctx.setLineWidth(max(1.5, s * 0.025))
    ctx.strokePath()

    // Shield silhouette
    let shield = CGMutablePath()
    shield.move(to: CGPoint(x: s * 0.50, y: s * 0.78))
    shield.addLine(to: CGPoint(x: s * 0.74, y: s * 0.66))
    shield.addLine(to: CGPoint(x: s * 0.74, y: s * 0.44))
    shield.addQuadCurve(to: CGPoint(x: s * 0.50, y: s * 0.20), control: CGPoint(x: s * 0.72, y: s * 0.26))
    shield.addQuadCurve(to: CGPoint(x: s * 0.26, y: s * 0.44), control: CGPoint(x: s * 0.28, y: s * 0.26))
    shield.addLine(to: CGPoint(x: s * 0.26, y: s * 0.66))
    shield.closeSubpath()

    ctx.addPath(shield)
    ctx.setFillColor(CGColor(red: 0.12, green: 0.48, blue: 0.78, alpha: 0.95))
    ctx.fillPath()
    ctx.addPath(shield)
    ctx.setStrokeColor(CGColor(red: 0.35, green: 0.85, blue: 1.0, alpha: 1.0))
    ctx.setLineWidth(max(1.5, s * 0.03))
    ctx.strokePath()

    // Checkmark inside shield
    let check = CGMutablePath()
    check.move(to: CGPoint(x: s * 0.39, y: s * 0.49))
    check.addLine(to: CGPoint(x: s * 0.47, y: s * 0.40))
    check.addLine(to: CGPoint(x: s * 0.63, y: s * 0.58))
    ctx.addPath(check)
    ctx.setStrokeColor(CGColor(red: 1.0, green: 1.0, blue: 1.0, alpha: 1.0))
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    ctx.setLineWidth(max(2.0, s * 0.055))
    ctx.strokePath()

    NSGraphicsContext.restoreGraphicsState()

    if let pngData = rep.representation(using: .png, properties: [:]) {
        try? pngData.write(to: URL(fileURLWithPath: "\(outDir)/\(filename)"))
    }
}

let specs: [(Int, String)] = [
    (16, "icon_16x16.png"),
    (32, "icon_16x16@2x.png"),
    (32, "icon_32x32.png"),
    (64, "icon_32x32@2x.png"),
    (128, "icon_128x128.png"),
    (256, "icon_128x128@2x.png"),
    (256, "icon_256x256.png"),
    (512, "icon_256x256@2x.png"),
    (512, "icon_512x512.png"),
    (1024, "icon_512x512@2x.png")
]

for (sz, name) in specs {
    renderIcon(size: sz, filename: name)
}
SWIFT_ICON

iconutil -c icns "${ICONSET_DIR}" -o "${APP_BUNDLE}/Contents/Resources/AppIcon.icns" || true
rm -rf "$(dirname "${ICONSET_DIR}")"

cat > "${APP_BUNDLE}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>${APP_NAME}</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Sentinal</string>
    <key>CFBundleDisplayName</key>
    <string>Sentinal</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.4.0</string>
    <key>CFBundleVersion</key>
    <string>140</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>
EOF

echo "==> Applying ad-hoc macOS code signature and clearing quarantine attributes..."
xattr -cr "${APP_BUNDLE}" || true
codesign --force --deep --sign - "${APP_BUNDLE}" >/dev/null 2>&1 || true

echo "==> Successfully packaged: ${APP_BUNDLE}"
