// pop_calc_dll.cpp — minimal "pops calc.exe" DLL
//
// Build (MSVC, Developer PowerShell):
//   cl /LD /EHsc /O2 /nologo pop_calc_dll.cpp /Fe:pop_calc_dll.dll
//
// Build (MinGW-w64):
//   x86_64-w64-mingw32-g++ -shared -O2 -s -o pop_calc_dll.dll pop_calc_dll.cpp \
//       -Wl,--subsystem,windows,--kill-at
//
// Use:
//   Inject into a target process via any of the techniques in
//   docs/SOLUTIONS/13-*.md through 18-*.md. When DllMain(DLL_PROCESS_ATTACH)
//   fires inside the host, calc.exe opens as a child of the host.
//
// Verify in Process Hacker / Process Explorer:
//   calc.exe should appear with the TARGET process as its parent.

#include <windows.h>

static DWORD WINAPI PopCalcThread(LPVOID) {
    WinExec("calc.exe", SW_SHOW);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Disable thread-attach/detach callbacks for perf and quiet.
        DisableThreadLibraryCalls(hMod);

        // Spawn a worker so DllMain returns quickly. The loader lock holds
        // during DllMain; calling WinExec directly here would work but is
        // bad practice (it does a lot and shouldn't run under the lock).
        CreateThread(nullptr, 0, PopCalcThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
