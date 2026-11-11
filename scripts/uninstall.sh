#!/usr/bin/env zsh
set -euo pipefail

echo "==> Uninstalling Website Security Checker..."

# 1. Remove application bundles if present
if [ -d "/Applications/WebsiteSecurityChecker.app" ]; then
    rm -rf "/Applications/WebsiteSecurityChecker.app"
    echo "Removed /Applications/WebsiteSecurityChecker.app"
fi

if [ -d "$(pwd)/dist/WebsiteSecurityChecker.app" ]; then
    rm -rf "$(pwd)/dist/WebsiteSecurityChecker.app"
    echo "Removed $(pwd)/dist/WebsiteSecurityChecker.app"
fi

# 2. Remove Application Support database & logs
APP_SUPPORT_DIR="${HOME}/Library/Application Support/WebsiteSecurityChecker"
if [ -d "${APP_SUPPORT_DIR}" ]; then
    rm -rf "${APP_SUPPORT_DIR}"
    echo "Removed ${APP_SUPPORT_DIR}"
fi

# 3. Remove stored AI API keys from macOS Keychain
for provider in "OpenAI" "Anthropic" "Google Gemini"; do
    security delete-generic-password -s "com.sentinel.WebsiteSecurityChecker.AIKeys" -a "${provider}" >/dev/null 2>&1 || true
done
echo "Removed Keychain items for com.sentinel.WebsiteSecurityChecker.AIKeys"

echo "==> Uninstallation complete."
