# Container Escape

Detect and exploit container misconfigurations to escape to the host.

## Files

| File | Description |
|------|-------------|
| [`docker_escape.sh`](docker_escape.sh) | Automated container escape assessment — Docker socket, privileged mode, capabilities, PID namespace, sensitive mounts, Kubernetes service account |
| [`container_breakout.md`](container_breakout.md) | Full breakout reference — Docker socket, nsenter, cgroup escape, CAP_SYS_ADMIN, CAP_SYS_PTRACE, K8s pod escape, kubelet API, containerd/CRI-O |

## MITRE ATT&CK References

| Technique | ID |
|-----------|----|
| Escape to Host | T1611 |
| Container Administration Command | T1609 |
| Exploitation for Privilege Escalation | T1068 |

## Quick Start

```bash
# Run automated assessment inside a container
chmod +x docker_escape.sh
./docker_escape.sh

# Quick checks
[ -S /var/run/docker.sock ] && echo "Docker socket — CRITICAL"
ip link add dummy0 type dummy 2>/dev/null && echo "Privileged!" && ip link delete dummy0
cat /proc/self/status | grep CapEff
```
