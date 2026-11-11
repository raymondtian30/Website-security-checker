#!/usr/bin/env zsh
set -euo pipefail

APP_NAME="WebsiteSecurityChecker"
BUNDLE_ID="com.sentinel.WebsiteSecurityChecker"
BUILD_DIR="$(pwd)/dist"
APP_BUNDLE="${BUILD_DIR}/${APP_NAME}.app"

echo "==> Building ${APP_NAME} (Release configuration)..."
swift build -c release --product "${APP_NAME}"

BIN_PATH="$(swift build -c release --show-bin-path)/${APP_NAME}"

echo "==> Creating macOS Application Bundle at ${APP_BUNDLE}..."
rm -rf "${APP_BUNDLE}"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

cp "${BIN_PATH}" "${APP_BUNDLE}/Contents/MacOS/${APP_NAME}"
chmod +x "${APP_BUNDLE}/Contents/MacOS/${APP_NAME}"

cat > "${APP_BUNDLE}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>${APP_NAME}</string>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Website Security Checker</string>
    <key>CFBundleDisplayName</key>
    <string>Website Security Checker</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
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

echo "==> Applying ad-hoc macOS code signature..."
codesign --force --deep --sign - "${APP_BUNDLE}" >/dev/null 2>&1 || true

echo "==> Successfully packaged: ${APP_BUNDLE}"
echo "To install to /Applications, run:"
echo "  cp -R \"${APP_BUNDLE}\" /Applications/"
