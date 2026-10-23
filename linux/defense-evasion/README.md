# Linux Defense Evasion

Techniques for evading detection during Linux security assessments.

## Files

| File | Description |
|------|-------------|
| [`log_tampering.md`](log_tampering.md) | Log manipulation — auth.log, syslog, wtmp/btmp binary editing, journalctl, auditd evasion, timestomping, immutable log detection, shell history cleanup |
| [`antivirus_evasion.md`](antivirus_evasion.md) | AV/EDR evasion — identify security controls, fileless execution (memfd_create, /dev/shm), obfuscation, living-off-the-land downloads, ptrace injection |
| [`firewall_evasion.md`](firewall_evasion.md) | Firewall bypass — iptables/nftables/ufw enumeration, DNS tunneling (iodine, dnscat2), ICMP tunneling, HTTP tunneling (chisel, ligolo), SSH tunneling, socat relays |

## MITRE ATT&CK

| Technique | ID |
|-----------|----|
| Indicator Removal | T1070 |
| Impair Defenses | T1562 |
| Obfuscated Files | T1027 |
| Protocol Tunneling | T1572 |
| Process Injection | T1055 |
