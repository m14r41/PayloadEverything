# macOS Persistence

Maintain access across reboots and logins on macOS targets.

**MITRE ATT&CK**: T1543.001/004 (Launch Agent/Daemon), T1547.015 (Login Items), T1053.003 (Cron)

## Files

| File | Description |
|------|-------------|
| [`launch_agent_persist.sh`](launch_agent_persist.sh) | LaunchAgent/LaunchDaemon persistence — 5 trigger types (RunAtLoad, StartInterval, WatchPaths, Calendar, KeepAlive), stealthy label names, install/remove/list |
| [`login_items.md`](login_items.md) | Login Items persistence — AppleScript, SMLoginItemSetEnabled, Login Hook, Folder Actions, shell profiles, calendar alarms |
| [`cron_persistence.sh`](cron_persistence.sh) | Cron/periodic/at persistence — user crontab, /etc/periodic scripts, at jobs, enumeration, cleanup |
| [`authorization_plugin.md`](authorization_plugin.md) | Authorization plugin persistence — Objective-C plugin template, runs as root at login before desktop loads, high stealth |

## Quick Start

```bash
# Install user LaunchAgent (no root needed)
./launch_agent_persist.sh install-agent

# Install system LaunchDaemon (root required)
sudo ./launch_agent_persist.sh install-daemon

# Add cron callback
./cron_persistence.sh install-cron

# List all persistence
./launch_agent_persist.sh list
./cron_persistence.sh list
```
