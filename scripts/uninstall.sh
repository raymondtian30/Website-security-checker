#!/usr/bin/env zsh
set -euo pipefail

echo "==> Uninstalling Website Security Checker..."

# 1. Remove application bundles if present
for app_path in "/Applications/Sentinal.app" "/Applications/WebsiteSecurityChecker.app" "$(pwd)/Sentinal.app" "$(pwd)/dist/WebsiteSecurityChecker.app"; do
    if [ -d "${app_path}" ]; then
        rm -rf "${app_path}"
        echo "Removed ${app_path}"
    fi
done

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
