<#
.SYNOPSIS
    DPAPI Decryption Helper — Decrypt data protected with Windows DPAPI.

.DESCRIPTION
    Many thick clients use DPAPI (CryptProtectData) to "encrypt" credentials.
    If running as the same user who encrypted the data, DPAPI decrypts it
    without needing a key — this is NOT secure storage.

    OWASP Thick Client: TC2 — Improper Credential Storage
    Severity: HIGH — DPAPI with CurrentUser scope is decryptable by any
    process running as that user.

.PARAMETER FilePath
    Path to file containing DPAPI-encrypted blob

.PARAMETER Base64
    Base64-encoded DPAPI blob (from registry or config)

.PARAMETER RegistryPath
    Registry path containing DPAPI-encrypted value

.PARAMETER ValueName
    Registry value name

.EXAMPLE
    .\dpapi_decrypt.ps1 -FilePath "C:\Users\user\AppData\Local\App\cred.dat"
    .\dpapi_decrypt.ps1 -Base64 "AQAAAA..."
    .\dpapi_decrypt.ps1 -RegistryPath "HKCU:\Software\App" -ValueName "Password"
#>

param(
    [string]$FilePath,
    [string]$Base64,
    [string]$RegistryPath,
    [string]$ValueName
)

Add-Type -AssemblyName System.Security

function Decrypt-DPAPI {
    param([byte[]]$EncryptedBytes)

    try {
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $EncryptedBytes,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    } catch {
        # Try LocalMachine scope
        try {
            $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $EncryptedBytes,
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
            return [System.Text.Encoding]::UTF8.GetString($decrypted)
        } catch {
            return $null
        }
    }
}

Write-Host "[*] DPAPI Decryption Helper`n" -ForegroundColor Cyan

$blob = $null

if ($FilePath) {
    if (-not (Test-Path $FilePath)) {
        Write-Host "[-] File not found: $FilePath" -ForegroundColor Red
        return
    }
    $blob = [System.IO.File]::ReadAllBytes($FilePath)
    Write-Host "[*] Source: File — $FilePath ($($blob.Length) bytes)"
}
elseif ($Base64) {
    try {
        $blob = [Convert]::FromBase64String($Base64)
        Write-Host "[*] Source: Base64 input ($($blob.Length) bytes)"
    } catch {
        Write-Host "[-] Invalid Base64 string" -ForegroundColor Red
        return
    }
}
elseif ($RegistryPath -and $ValueName) {
    if (-not (Test-Path $RegistryPath)) {
        Write-Host "[-] Registry path not found: $RegistryPath" -ForegroundColor Red
        return
    }
    $regValue = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
    if ($regValue -is [byte[]]) {
        $blob = $regValue
    } elseif ($regValue -is [string]) {
        try { $blob = [Convert]::FromBase64String($regValue) } catch {}
    }
    if (-not $blob) {
        Write-Host "[-] Could not read registry value as bytes" -ForegroundColor Red
        return
    }
    Write-Host "[*] Source: Registry — ${RegistryPath}\${ValueName} ($($blob.Length) bytes)"
}
else {
    Write-Host "Usage: Provide -FilePath, -Base64, or -RegistryPath + -ValueName"
    return
}

# Check DPAPI header
if ($blob.Length -ge 4 -and $blob[0] -eq 1 -and $blob[1] -eq 0 -and $blob[2] -eq 0 -and $blob[3] -eq 0) {
    Write-Host "[+] DPAPI blob header detected (0x01000000)" -ForegroundColor Green
} else {
    Write-Host "[?] No standard DPAPI header — attempting decryption anyway" -ForegroundColor Yellow
}

$result = Decrypt-DPAPI -EncryptedBytes $blob

if ($result) {
    Write-Host "`n[+] DECRYPTED SUCCESSFULLY:" -ForegroundColor Green
    Write-Host "    $result" -ForegroundColor White
    Write-Host "`n[!] FINDING: Application uses DPAPI without additional entropy." -ForegroundColor Red
    Write-Host "    Any process running as this user can decrypt stored credentials."
    Write-Host "    Severity: HIGH"
} else {
    Write-Host "`n[-] Decryption failed." -ForegroundColor Yellow
    Write-Host "    Possible reasons:"
    Write-Host "    - Different user encrypted the data"
    Write-Host "    - Additional entropy (optional entropy parameter) was used"
    Write-Host "    - Not a DPAPI blob"
    Write-Host "    - Machine-scope DPAPI from different machine"
    Write-Host "`n    Try with Mimikatz: dpapi::blob /in:file /unprotect"
}
