#!/usr/bin/env bash
# Description: Scans for Axios supply chain attack dependencies and system IOCs.

set -euo pipefail

# --- Configuration ---
OUTPUT_FILE="scanresult_ioc.log"
SEARCH_DIR="${1:-$(pwd)}"

# Initialize log file
> "$OUTPUT_FILE"

echo "🚨 Starting Axios Supply Chain Threat Scanner 🚨"
echo "🔍 Scanning directory: $(realpath "$SEARCH_DIR")"
echo "📁 Output log: $(realpath "$OUTPUT_FILE")"
echo "--------------------------------------------------------"

# --- Phase 1: Dependency Manifest Scanning ---
echo "[*] Phase 1: Scanning lockfiles and manifests for compromised versions..."

# Regex pattern catching: axios@1.14.1, axios@0.30.4, plain-crypto-js@4.2.1
# Handles JSON format ("axios": "1.14.1") and lockfile formats (axios@1.14.1)
PKG_PATTERN="(axios[\"']?\s*:\s*[\"']?[~^]?|axios@)(1\.14\.1|0\.30\.4)|(plain-crypto-js[\"']?\s*:\s*[\"']?[~^]?|plain-crypto-js@)4\.2\.1"

find "$(realpath "$SEARCH_DIR")" -type f \
    \( -name "package.json" -o -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) -print0 | 
while IFS= read -r -d '' file; do
    if grep -qEi "$PKG_PATTERN" "$file"; then
        echo "[!] COMPROMISED DEPENDENCY DETECTED: $file"
        echo "DEPENDENCY_MATCH: $file" >> "$OUTPUT_FILE"
    fi
done

# --- Phase 2: System-Level IOC Scanning ---
echo "[*] Phase 2: Scanning local system for dropped RAT payloads..."
OS_TYPE="$(uname -s)"

check_system_ioc() {
    local target_file="$1"
    if [[ -f "$target_file" || -d "$target_file" ]]; then
        echo "[!] CRITICAL: System IOC found at $target_file"
        echo "SYSTEM_IOC: $target_file" >> "$OUTPUT_FILE"
    fi
}

case "$OS_TYPE" in
    Darwin)
        # macOS IOC
        check_system_ioc "/Library/Caches/com.apple.act.mond"
        ;;
    Linux)
        # Linux IOC
        check_system_ioc "/tmp/ld.py"
        ;;
    MINGW*|CYGWIN*|MSYS*)
        # Windows environments (Git Bash, etc.)
        # Expanding Windows environment variables in Bash can be tricky, using common absolute paths
        check_system_ioc "C:/ProgramData/wt"
        # Not reliably scanning %TEMP%\6202033.vbs/.ps1 as they exist briefly during execution,
        # but the /wt folder is a persistent indicator.
        ;;
    *)
        echo "[-] Unknown OS type ($OS_TYPE) - skipping OS-specific payload checks."
        ;;
esac

echo "--------------------------------------------------------"
MATCHES=$(wc -l < "$OUTPUT_FILE" | tr -d ' ')

if [[ $MATCHES -gt 0 ]]; then
    echo "❌ VULNERABILITY FOUND: $MATCHES indicator(s) detected."
    echo "Please review '$(realpath "$OUTPUT_FILE")' immediately."
    echo "WARNING: If an IOC was found, consider this machine fully compromised. Rotate all secrets (cloud keys, npm tokens, deploy keys) immediately."
    exit 1
else
    echo "✅ Scan complete. No IOCs detected in the specified paths."
    exit 0
fi
