#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# build_injectors.sh - interactive cross-compiler for process-injection-1
#
# Compiles any or all of the 10 injector sources in this folder to Windows
# PE executables using mingw-w64 on Linux. Pick an arch (x64 / x86 / both)
# and which injector(s) to build from a numbered menu.
#
# No LHOST/LPORT baked into these injectors (unlike the reverse-shell DLL
# in process-injection-2) - every injector takes its target PID / name
# at runtime, so there is nothing network-related to validate here.
#
# Standalone mode: if the .cpp sources are not next to this script, they
# are fetched from the GitHub raw URL on first use.
# ---------------------------------------------------------------------------

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$HERE"
CONF="$HERE/build_injectors.conf"

SRC_BASE="https://raw.githubusercontent.com/m14r41/PayloadEverything/main/thick-client/process-injection-1"

# ---- source table: cpp filename | output basename | extra link libs ----
# Keep the order stable so the menu numbering does not shift between runs.
SOURCES=(
    "classic_injection.cpp:inject:"
    "classic_injection_v2.cpp:inject_v2:"
    "dll_injection.cpp:dll_inject:-lpsapi"
    "dll_injection_v2.cpp:dll_inject_v2:-lpsapi"
    "apc_injection.cpp:apc_inject:"
    "apc_injection_v2.cpp:apc_inject_v2:"
    "process_hollowing.cpp:hollow:"
    "process_hollowing_v2.cpp:hollow_v2:"
    "shellcode_runner.cpp:runner:"
    "shellcode_runner_v2.cpp:runner_v2:"
)

# ---- colors (auto-off when stdout is not a TTY) ----
if [[ -t 1 ]]; then
    G='\033[92m'; R='\033[91m'; Y='\033[93m'; C='\033[96m'; B='\033[1m'; N='\033[0m'
else
    G=''; R=''; Y=''; C=''; B=''; N=''
fi

# ---- tool availability + auto-install ----
apt_install() {
    local pkg="$1"
    if dpkg -s "$pkg" >/dev/null 2>&1; then return 0; fi
    echo -e "${Y}[*]${N} installing apt package : ${C}$pkg${N}"
    sudo apt-get update -qq >/dev/null 2>&1 || true
    sudo apt-get install -y "$pkg"
}

ensure_downloader() {
    if command -v curl >/dev/null 2>&1; then return 0; fi
    if command -v wget >/dev/null 2>&1; then return 0; fi
    apt_install curl
}

ensure_mingw_x64() {
    command -v x86_64-w64-mingw32-g++     >/dev/null 2>&1 || apt_install mingw-w64
    command -v x86_64-w64-mingw32-windres >/dev/null 2>&1 || apt_install mingw-w64
}

ensure_mingw_x86() {
    command -v i686-w64-mingw32-g++     >/dev/null 2>&1 || apt_install mingw-w64
    command -v i686-w64-mingw32-windres >/dev/null 2>&1 || apt_install mingw-w64
}

# ---- helpers ----
banner() {
    echo
    echo -e "${G}${B}================================================================${N}"
    echo -e "${G}${B}  process-injection-1 - interactive injector builder${N}"
    echo -e "${G}${B}================================================================${N}"
    echo
}

prompt() {
    # $1 = label, $2 = default
    local v
    read -r -p "$(echo -e "${Y}?${N} $1 [${C}$2${N}]: ")" v
    echo "${v:-$2}"
}

# Validate "1..N" or "N,M,..." or "all" / "a"
parse_selection() {
    local raw="$1" max="$2"
    if [[ "$raw" == "all" || "$raw" == "a" ]]; then
        seq 1 "$max"
        return 0
    fi
    # strip spaces, split on comma
    raw="${raw// /}"
    IFS=',' read -ra parts <<< "$raw"
    for p in "${parts[@]}"; do
        if ! [[ "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > max )); then
            return 1
        fi
        echo "$p"
    done
}

download_source() {
    local file="$1"
    local dest="$HERE/$file"
    [[ -f "$dest" ]] && return 0
    ensure_downloader
    echo -e "${Y}[*]${N} fetching missing source : ${C}$file${N}"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$SRC_BASE/$file" -o "$dest" || return 1
    else
        wget -q "$SRC_BASE/$file" -O "$dest" || return 1
    fi
    # sanity: must contain a C/C++ include
    if ! grep -q '#include' "$dest" 2>/dev/null; then
        echo -e "${R}[!]${N} downloaded file does not look like a source : $file"
        rm -f "$dest"
        return 1
    fi
    return 0
}

# Return the triple-colon fields of SOURCES[index]
src_field() {
    local idx="$1" field="$2"
    local row="${SOURCES[$((idx-1))]}"
    IFS=':' read -r src out libs <<< "$row"
    case "$field" in
        src)  echo "$src"  ;;
        out)  echo "$out"  ;;
        libs) echo "$libs" ;;
    esac
}

show_menu() {
    echo "Pick which injector(s) to build (comma-separated numbers, or 'all'):"
    local n=1
    for row in "${SOURCES[@]}"; do
        IFS=':' read -r src out libs <<< "$row"
        printf "  ${C}%2d${N}) %-28s -> %s.exe\n" "$n" "$src" "$out"
        ((n++))
    done
    echo -e "  ${C}all${N} ) build every injector"
    echo
}

build_one() {
    local idx="$1" arch="$2"
    local src out libs cxx wres out_exe rc_obj
    src="$(src_field  "$idx" src)"
    out="$(src_field  "$idx" out)"
    libs="$(src_field "$idx" libs)"

    case "$arch" in
        x64) cxx="x86_64-w64-mingw32-g++"; wres="x86_64-w64-mingw32-windres" ;;
        x86) cxx="i686-w64-mingw32-g++"  ; wres="i686-w64-mingw32-windres"   ;;
    esac

    out_exe="$OUT_DIR/${out}_${arch}.exe"

    # ensure the source is present
    download_source "$src" || return 1

    # shellcode_runner_v2 also needs its .rc compiled
    local extra_obj=""
    if [[ "$src" == "shellcode_runner_v2.cpp" ]]; then
        download_source "shellcode_runner_v2.rc" || return 1
        rc_obj="$(mktemp --suffix=.o)"
        if ! "$wres" "$HERE/shellcode_runner_v2.rc" -o "$rc_obj" 2>/dev/null; then
            echo -e "    ${R}${B}fail${N}  (windres failed on shellcode_runner_v2.rc)"
            rm -f "$rc_obj"
            return 1
        fi
        extra_obj="$rc_obj"
    fi

    echo
    echo -e "${G}[+]${N} building ${C}$src${N} (${C}$arch${N}) -> ${C}$out_exe${N}"
    echo -e "    compiler = ${C}$cxx${N}"

    # -std=c++20       : files use C99 designated initializers
    # -static-*        : no MinGW runtime deps on the victim
    # -fno-exceptions  : smaller binary (no C++ EH table)
    # -O2 -s           : optimize and strip symbols
    if "$cxx" -std=c++20 -O2 -s \
              -static -static-libgcc -static-libstdc++ \
              -fno-exceptions -fno-rtti \
              -o "$out_exe" "$HERE/$src" $extra_obj $libs \
              -Wl,--subsystem,console; then
        local bytes; bytes="$(stat -c '%s' "$out_exe" 2>/dev/null || wc -c < "$out_exe")"
        echo -e "    ${G}${B}ok${N}  $(printf '%d' "$bytes") bytes"
        [[ -n "$extra_obj" ]] && rm -f "$extra_obj"
        return 0
    else
        echo -e "    ${R}${B}fail${N}"
        [[ -n "$extra_obj" ]] && rm -f "$extra_obj"
        return 1
    fi
}

save_conf() {
    cat > "$CONF" <<EOF
# written by build_injectors.sh - edit or delete freely
LAST_SELECTION="$LAST_SELECTION"
LAST_ARCH="$LAST_ARCH"
EOF
}

# ---- main ----
# load previous selections from conf (optional convenience)
LAST_SELECTION=""; LAST_ARCH=""
[[ -f "$CONF" ]] && source "$CONF"

main() {
    banner
    echo -e "${G}[+]${N} folder : ${C}$HERE${N}"
    echo -e "${G}[+]${N} output : ${C}$OUT_DIR/<name>_<arch>.exe${N}"
    echo
    show_menu

    local raw selection_default="${LAST_SELECTION:-all}"
    local sel=""
    while true; do
        raw="$(prompt "selection" "$selection_default")"
        if sel=$(parse_selection "$raw" "${#SOURCES[@]}" 2>/dev/null); then
            break
        fi
        echo -e "${R}[!]${N} invalid selection : '$raw' (use comma-separated numbers 1..${#SOURCES[@]} or 'all')"
    done
    LAST_SELECTION="$raw"

    echo
    echo "Pick architecture:"
    echo -e "  ${C}1${N}) x64   (AMD64 - most Windows targets)"
    echo -e "  ${C}2${N}) x86   (32-bit / WOW64 - legacy apps)"
    echo -e "  ${C}3${N}) both  (produce <name>_x64.exe AND <name>_x86.exe)"
    echo
    local arch_default="${LAST_ARCH:-1}"
    local arch_choice=""
    while true; do
        arch_choice="$(prompt "choice" "$arch_default")"
        if [[ "$arch_choice" =~ ^[1-3]$ ]]; then break; fi
        echo -e "${R}[!]${N} invalid choice : '$arch_choice' (expected 1, 2 or 3)"
    done
    LAST_ARCH="$arch_choice"

    local -a ARCHES=()
    case "$arch_choice" in
        1) ARCHES=(x64)      ;;
        2) ARCHES=(x86)      ;;
        3) ARCHES=(x64 x86)  ;;
    esac

    # ensure cross-compilers before kicking off a batch
    for a in "${ARCHES[@]}"; do
        case "$a" in
            x64) ensure_mingw_x64 ;;
            x86) ensure_mingw_x86 ;;
        esac
    done

    local fails=0
    for idx in $sel; do
        for a in "${ARCHES[@]}"; do
            build_one "$idx" "$a" || ((fails++))
        done
    done

    save_conf

    echo
    if (( fails == 0 )); then
        echo -e "${G}${B}[+] done${N}  (settings saved to ${C}$CONF${N})"
    else
        echo -e "${Y}${B}[*] done${N}  ${R}${fails}${N} build(s) failed"
    fi
    ls -lh "$OUT_DIR"/*_x64.exe "$OUT_DIR"/*_x86.exe 2>/dev/null | sed 's/^/    /' || true
    echo
    echo -e "${Y}next:${N}  copy the .exe(s) to the victim and run them"
    echo -e "        example:  ${C}inject_x64.exe <PID or name>${N}"
    echo -e "        example:  ${C}dll_inject_x64.exe <PID> C:\\\\path\\\\to\\\\payload.dll${N}"
    echo
}

main "$@"
