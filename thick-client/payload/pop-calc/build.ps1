# payloads/pop-calc/build.ps1 — builds pop_calc.exe and pop_calc_dll.dll
# Auto-detects MSVC first, falls back to MinGW-w64.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\build.ps1

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Have-Cmd($name) { $null -ne (Get-Command $name -ErrorAction SilentlyContinue) }

if (Have-Cmd 'cl') {
    Write-Host "[*] Using MSVC (cl.exe)" -ForegroundColor Cyan
    cl /EHsc /O2 /nologo pop_calc.cpp     /link /SUBSYSTEM:WINDOWS /Fe:pop_calc.exe       | Out-Null
    cl /LD /EHsc /O2 /nologo pop_calc_dll.cpp /Fe:pop_calc_dll.dll                        | Out-Null
}
elseif (Have-Cmd 'x86_64-w64-mingw32-g++') {
    Write-Host "[*] Using MinGW-w64" -ForegroundColor Cyan
    x86_64-w64-mingw32-g++ -O2 -s -mwindows -o pop_calc.exe pop_calc.cpp
    x86_64-w64-mingw32-g++ -shared -O2 -s -o pop_calc_dll.dll pop_calc_dll.cpp `
        -Wl,--subsystem,windows,--kill-at
}
else {
    Write-Host "[!] Neither 'cl' nor 'x86_64-w64-mingw32-g++' found on PATH." -ForegroundColor Red
    Write-Host "    Install one of:" -ForegroundColor Red
    Write-Host "      - Visual Studio Build Tools (then open 'Developer PowerShell for VS')"
    Write-Host "      - MinGW-w64 (choco install mingw / scoop install gcc / apt install mingw-w64)"
    exit 1
}

Write-Host "`n[+] Built:" -ForegroundColor Green
Get-ChildItem *.exe,*.dll | Where-Object { $_.Name -like "pop_calc*" } |
    Select-Object Name,@{N='KB';E={[math]::Round($_.Length/1KB,1)}} | Format-Table -AutoSize

# Cleanup intermediate artifacts
Get-ChildItem *.obj,*.exp,*.lib -ErrorAction SilentlyContinue | Remove-Item
