<#
.SYNOPSIS
    Extract hardcoded/stored credentials from desktop applications.

.DESCRIPTION
    Thick clients commonly store credentials insecurely:
    - Plaintext in config files, registry, SQLite DBs
    - Weakly encrypted (base64, XOR, DPAPI without additional entropy)
    - Hardcoded in binaries
    - Connection strings with embedded passwords

    OWASP Thick Client Top 10: TC2 — Improper Credential Storage

.PARAMETER AppPath
    Path to the target application directory

.PARAMETER AppName
    Application process or registry name

.EXAMPLE
    .\extract_credentials.ps1 -AppPath "C:\Program Files\TargetApp" -AppName "TargetApp"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$AppPath,
    [string]$AppName = ""
)

$ErrorActionPreference = "SilentlyContinue"

if (-not $AppName) {
    $AppName = Split-Path $AppPath -Leaf
}

$reportLines = @()
function Log($severity, $msg) {
    $prefix = switch ($severity) {
        "CRITICAL" { "[!!!]" }
        "HIGH"     { "[!!]"  }
        "MEDIUM"   { "[!]"   }
        "INFO"     { "[*]"   }
    }
    $line = "$prefix [$severity] $msg"
    Write-Host $line -ForegroundColor $(switch ($severity) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Red" }
        "MEDIUM"   { "Yellow" }
        "INFO"     { "Cyan" }
    })
    $script:reportLines += $line
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Thick Client Credential Extractor" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
Log "INFO" "Target: $AppPath"
Log "INFO" "App Name: $AppName"

# ============================================================
# 1. Config files — plaintext credentials
# ============================================================
Write-Host "`n--- Config File Analysis ---" -ForegroundColor Yellow

$configPatterns = @("*.config", "*.ini", "*.xml", "*.json", "*.yaml", "*.yml",
                     "*.properties", "*.cfg", "*.conf", "*.settings", "*.dat",
                     "*.sqlite", "*.db", "*.sdf", "*.mdf", "*.log")

$sensitivePatterns = @(
    "password", "passwd", "pwd", "secret", "apikey", "api_key", "api-key",
    "token", "connectionstring", "conn_str", "connstr", "credential",
    "private_key", "privatekey", "auth", "bearer", "jdbc:", "server=",
    "data source=", "user id=", "integrated security=false"
)

$configFiles = Get-ChildItem -Path $AppPath -Recurse -Include $configPatterns -ErrorAction SilentlyContinue
foreach ($file in $configFiles) {
    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content) { continue }

    foreach ($pattern in $sensitivePatterns) {
        if ($content -imatch $pattern) {
            # Extract the matching line
            $lines = $content -split "`n"
            $matchLines = $lines | Where-Object { $_ -imatch $pattern }
            foreach ($ml in $matchLines) {
                $trimmed = $ml.Trim()
                if ($trimmed.Length -gt 200) { $trimmed = $trimmed.Substring(0, 200) + "..." }
                Log "HIGH" "Credential in config: $($file.FullName)"
                Log "HIGH" "  Match: $trimmed"
            }
            break
        }
    }
}

# ============================================================
# 2. Registry — stored credentials
# ============================================================
Write-Host "`n--- Registry Analysis ---" -ForegroundColor Yellow

$regPaths = @(
    "HKCU:\Software\$AppName",
    "HKLM:\Software\$AppName",
    "HKCU:\Software\WOW6432Node\$AppName",
    "HKLM:\Software\WOW6432Node\$AppName"
)

foreach ($regPath in $regPaths) {
    if (Test-Path $regPath) {
        Log "INFO" "Registry key found: $regPath"
        try {
            $props = Get-ItemProperty -Path $regPath -ErrorAction Stop
            $props.PSObject.Properties | ForEach-Object {
                $name = $_.Name
                $value = $_.Value
                if ($name -match "PSPath|PSParentPath|PSChildName|PSProvider|PSDrive") { return }

                foreach ($sp in $sensitivePatterns) {
                    if ($name -imatch $sp) {
                        Log "CRITICAL" "Credential in registry: $regPath\$name = $value"
                    }
                }
                # Check for base64-encoded values
                if ($value -is [string] -and $value.Length -gt 20 -and $value -match '^[A-Za-z0-9+/=]+$') {
                    try {
                        $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($value))
                        if ($decoded -match "[\x20-\x7E]{4,}") {
                            Log "HIGH" "Base64 value in registry: $regPath\$name"
                            Log "HIGH" "  Decoded: $decoded"
                        }
                    } catch {}
                }
            }
        } catch {}

        # Check subkeys recursively
        try {
            Get-ChildItem -Path $regPath -Recurse -ErrorAction Stop | ForEach-Object {
                $subProps = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if ($subProps) {
                    $subProps.PSObject.Properties | ForEach-Object {
                        $name = $_.Name
                        if ($name -match "PSPath|PSParentPath|PSChildName|PSProvider|PSDrive") { return }
                        foreach ($sp in $sensitivePatterns) {
                            if ($name -imatch $sp) {
                                Log "CRITICAL" "Credential in registry subkey: $($_.Name) = $($_.Value)"
                            }
                        }
                    }
                }
            }
        } catch {}
    }
}

# ============================================================
# 3. SQLite databases — stored credentials
# ============================================================
Write-Host "`n--- SQLite/Database Analysis ---" -ForegroundColor Yellow

$dbFiles = Get-ChildItem -Path $AppPath -Recurse -Include @("*.sqlite", "*.db", "*.sdf", "*.sqlite3") -ErrorAction SilentlyContinue
foreach ($dbFile in $dbFiles) {
    Log "MEDIUM" "Database file found: $($dbFile.FullName) ($($dbFile.Length) bytes)"
    Log "INFO" "  Inspect with: sqlite3 '$($dbFile.FullName)' .tables"
    Log "INFO" "  Or use: DB Browser for SQLite"

    # Quick header check
    $header = [System.IO.File]::ReadAllBytes($dbFile.FullName) | Select-Object -First 16
    $headerStr = [System.Text.Encoding]::ASCII.GetString($header)
    if ($headerStr -match "SQLite") {
        Log "HIGH" "  Confirmed SQLite database — may contain credentials"
    }
}

# ============================================================
# 4. Binary strings — hardcoded secrets
# ============================================================
Write-Host "`n--- Binary String Analysis ---" -ForegroundColor Yellow

$binFiles = Get-ChildItem -Path $AppPath -Include @("*.exe", "*.dll") -ErrorAction SilentlyContinue
foreach ($binFile in $binFiles) {
    # Extract printable strings (basic approach)
    $bytes = [System.IO.File]::ReadAllBytes($binFile.FullName)
    $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)

    # Look for connection strings
    if ($ascii -imatch "server=.*password=") {
        Log "CRITICAL" "Connection string with password in: $($binFile.Name)"
    }
    if ($ascii -imatch "Data Source=.*Password=") {
        Log "CRITICAL" "SQL connection string in: $($binFile.Name)"
    }
    if ($ascii -imatch "jdbc:") {
        Log "HIGH" "JDBC connection string in: $($binFile.Name)"
    }
    if ($ascii -imatch "mongodb://.*:.*@") {
        Log "HIGH" "MongoDB connection URI in: $($binFile.Name)"
    }

    # Look for API keys/tokens patterns
    if ($ascii -match "(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}") {
        Log "CRITICAL" "Possible AWS Access Key in: $($binFile.Name)"
    }
    if ($ascii -match "eyJ[A-Za-z0-9_-]{10,}\.eyJ") {
        Log "HIGH" "JWT token in: $($binFile.Name)"
    }
}

# ============================================================
# 5. DPAPI / Windows Credential Manager
# ============================================================
Write-Host "`n--- DPAPI / Credential Manager ---" -ForegroundColor Yellow

# Check Windows Credential Manager
try {
    $creds = cmdkey /list 2>$null
    $appCreds = $creds | Select-String -Pattern $AppName -Context 0,3
    if ($appCreds) {
        Log "HIGH" "Credentials found in Windows Credential Manager for $AppName"
        $appCreds | ForEach-Object { Log "INFO" "  $_" }
    }
} catch {}

# Check for DPAPI blobs in AppData
$dpApiPaths = @(
    "$env:APPDATA\$AppName",
    "$env:LOCALAPPDATA\$AppName"
)
foreach ($dp in $dpApiPaths) {
    if (Test-Path $dp) {
        Log "INFO" "App data directory: $dp"
        $blobFiles = Get-ChildItem -Path $dp -Recurse -ErrorAction SilentlyContinue
        foreach ($bf in $blobFiles) {
            if ($bf.Length -gt 0 -and $bf.Length -lt 10000) {
                $firstBytes = [System.IO.File]::ReadAllBytes($bf.FullName) | Select-Object -First 4
                # DPAPI blob starts with 0x01000000
                if ($firstBytes.Count -ge 4 -and $firstBytes[0] -eq 1 -and $firstBytes[1] -eq 0 -and $firstBytes[2] -eq 0 -and $firstBytes[3] -eq 0) {
                    Log "HIGH" "DPAPI blob found: $($bf.FullName)"
                    Log "INFO" "  Decrypt with: [Security.Cryptography.ProtectedData]::Unprotect()"
                }
            }
        }
    }
}

# ============================================================
# 6. Report
# ============================================================
Write-Host "`n--- Summary ---" -ForegroundColor Cyan
$critCount = ($reportLines | Where-Object { $_ -match "\[CRITICAL\]" }).Count
$highCount = ($reportLines | Where-Object { $_ -match "\[HIGH\]" }).Count
$medCount = ($reportLines | Where-Object { $_ -match "\[MEDIUM\]" }).Count

Log "INFO" "Findings: $critCount Critical, $highCount High, $medCount Medium"

# Save report
$reportPath = Join-Path (Split-Path $MyInvocation.MyCommand.Path -Parent) "cred_extraction_report.txt"
$reportLines | Out-File -FilePath $reportPath -Encoding utf8
Log "INFO" "Report saved: $reportPath"
