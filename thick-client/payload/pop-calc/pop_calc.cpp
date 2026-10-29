// pop_calc.cpp — minimal "pops calc.exe" EXE
//
// Build (MSVC, Developer PowerShell):
//   cl /EHsc /O2 /nologo pop_calc.cpp /link /SUBSYSTEM:WINDOWS /Fe:pop_calc.exe
//
// Build (MinGW-w64, Windows or Linux cross-compile):
//   x86_64-w64-mingw32-g++ -O2 -s -mwindows -o pop_calc.exe pop_calc.cpp
//
// Run:
//   .\pop_calc.exe
// Expected: calc.exe opens as a child of pop_calc.exe
//
// Used for: process hollowing (#15), as the replacement PE in RunPE;
// also handy as a sanity check that your build toolchain works.

#include <windows.h>

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // WinExec is deprecated but tiny and reliable for a PoC.
    // Returns > 31 on success.
    WinExec("calc.exe", SW_SHOW);

    // Keep the host process alive briefly so hollowed targets don't exit
    // immediately before the UI appears. Remove this if you want fire-and-forget.
    Sleep(2000);
    return 0;
}
