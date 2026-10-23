# Broken Function Level Authorization (BFLA)

> **OWASP API**: API5 — Broken Function Level Authorization

## Files

| File | Description |
|------|-------------|
| [`bfla_test_patterns.md`](bfla_test_patterns.md) | Admin endpoint discovery, method tampering, role escalation, tenant boundary bypass |

## Quick Test

```bash
# Replay admin request with regular user token
curl -H "Authorization: Bearer <REGULAR_USER_TOKEN>" https://api.target.com/api/v1/admin/users

# Verb tunneling
curl -X POST -H "X-HTTP-Method-Override: DELETE" -H "Authorization: Bearer <USER_TOKEN>" https://api.target.com/api/v1/users/123
```
