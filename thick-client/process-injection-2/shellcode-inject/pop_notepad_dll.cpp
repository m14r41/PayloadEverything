// pop_notepad_dll.cpp - spawns notepad.exe when DLL loaded
// Build: cl /LD /EHsc /O2 /nologo pop_notepad_dll.cpp /link /OUT:pop_notepad_dll.dll
#include <windows.h>
static DWORD WINAPI PopThread(LPVOID) {
    WinExec("notepad.exe", SW_SHOW);
    return 0;
}
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(nullptr, 0, PopThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
