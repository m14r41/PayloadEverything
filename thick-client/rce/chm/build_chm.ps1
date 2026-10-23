<#
.SYNOPSIS
    Build a CHM payload from HTML source files.

.DESCRIPTION
    Creates a .hhp project file and compiles it using hhc.exe (HTML Help Compiler).
    If hhc.exe is not installed, provides nishang Out-CHM alternative.

.PARAMETER HtmlFile
    Path to the HTML payload file

.PARAMETER OutputChm
    Output CHM filename (default: payload.chm)

.PARAMETER Title
    Help file title (default: "Application Help")

.EXAMPLE
    .\build_chm.ps1 -HtmlFile chm_rce.html -OutputChm help.chm
#>

param(
    [string]$HtmlFile = "chm_rce.html",
    [string]$OutputChm = "payload.chm",
    [string]$Title = "Application Help"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "[*] CHM Payload Builder" -ForegroundColor Cyan

# Check for HTML Help Workshop
$hhcPaths = @(
    "${env:ProgramFiles(x86)}\HTML Help Workshop\hhc.exe",
    "${env:ProgramFiles}\HTML Help Workshop\hhc.exe",
    "C:\Program Files (x86)\HTML Help Workshop\hhc.exe"
)

$hhc = $null
foreach ($path in $hhcPaths) {
    if (Test-Path $path) {
        $hhc = $path
        break
    }
}

# Generate .hhp project file
$hhpContent = @"
[OPTIONS]
Compatibility=1.1 or later
Compiled file=$OutputChm
Default topic=$HtmlFile
Display compile progress=No
Language=0x409 English (United States)
Title=$Title

[FILES]
$HtmlFile
"@

$hhpFile = Join-Path $scriptDir "project.hhp"
Set-Content -Path $hhpFile -Value $hhpContent -Encoding utf8

if ($hhc) {
    Write-Host "[+] Found hhc.exe at: $hhc"
    Write-Host "[*] Compiling CHM..."

    # hhc.exe returns 1 on success (yes, really)
    & $hhc $hhpFile
    $chmPath = Join-Path $scriptDir $OutputChm

    if (Test-Path $chmPath) {
        Write-Host "[+] CHM created: $chmPath" -ForegroundColor Green
        Write-Host "[*] File size: $((Get-Item $chmPath).Length) bytes"
    } else {
        Write-Host "[-] Compilation may have failed. Check output above." -ForegroundColor Red
    }
} else {
    Write-Host "[-] hhc.exe not found." -ForegroundColor Yellow
    Write-Host @"

Install HTML Help Workshop:
  https://web.archive.org/web/2023/https://www.microsoft.com/en-us/download/details.aspx?id=21138

Alternative — use nishang Out-CHM (PowerShell):
  Import-Module nishang/Client/Out-CHM.ps1
  Out-CHM -Payload "calc.exe" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"

Alternative — use sharpchm or other tools:
  pip install pychm
"@
}

# Cleanup
if (Test-Path $hhpFile) {
    Remove-Item $hhpFile -Force
}
