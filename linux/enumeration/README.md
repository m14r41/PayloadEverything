# Linux Enumeration

Automated host reconnaissance for Linux VAPT engagements.

## Files

| File | Description |
|------|-------------|
| [`linux_enum.sh`](linux_enum.sh) | Comprehensive enumeration — OS, kernel, users, sudo, SUID/SGID, capabilities, cron, writable dirs, processes, network, SSH, sensitive files, containers, PATH analysis |

## Usage

```bash
chmod +x linux_enum.sh
./linux_enum.sh                    # output to /tmp/linux_enum_<timestamp>.txt
./linux_enum.sh /tmp/results.txt   # custom output path
```

## What It Checks

| Category | Details |
|----------|---------|
| OS & Kernel | Version, architecture, uptime, known CVE version checks |
| Users | UID 0 accounts, sudo/wheel group, shadow file permissions |
| Sudo | sudo -l, sudoers, sudoers.d, version (CVE checks) |
| SUID/SGID | All SUID binaries, cross-referenced against GTFOBins list |
| Capabilities | Dangerous capabilities (CAP_SETUID, CAP_SYS_ADMIN, etc.) |
| Cron | All cron sources, writable cron scripts detection |
| Writable Files | /etc/passwd, shadow, sudoers, crontab writability |
| Network | Listeners, routes, NFS exports (no_root_squash), iptables |
| SSH | Private keys, authorized_keys, agent forwarding |
| Credentials | History files, .env, database configs, cloud CLI creds |
| Containers | Docker socket, .dockerenv, cgroup detection |
| PATH | Writable PATH directories |
