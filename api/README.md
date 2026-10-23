# API Security Payloads

> **Status**: Active

Payloads, scripts, and testing methodology for REST, GraphQL, and API security assessments, mapped to the [OWASP API Security Top 10](https://owasp.org/www-project-api-security/).

## Directory Structure

| Folder | File | Description |
|--------|------|-------------|
| [bola/](bola/) | [bola_test_patterns.md](bola/bola_test_patterns.md) | IDOR patterns — numeric/UUID/encoded IDs, GraphQL nodes, method switch |
| [broken-auth/](broken-auth/) | [jwt_attacks.py](broken-auth/jwt_attacks.py) | JWT attack tool — none alg, confusion, brute-force, tamper, KID, JKU |
| | [jwt_common_secrets.txt](broken-auth/jwt_common_secrets.txt) | 100+ weak JWT secrets wordlist for brute-force |
| | [auth_bypass_headers.md](broken-auth/auth_bypass_headers.md) | IP spoofing, role escalation, verb tunneling headers |
| [bfla/](bfla/) | [bfla_test_patterns.md](bfla/bfla_test_patterns.md) | Admin endpoint discovery, method tampering, role escalation |
| [mass-assignment/](mass-assignment/) | [mass_assignment_payloads.json](mass-assignment/mass_assignment_payloads.json) | 40+ fields — privilege, billing, status, feature flags |
| [rate-limit/](rate-limit/) | [rate_limit_bypass.md](rate-limit/rate_limit_bypass.md) | IP header rotation, URL tricks, GraphQL batching, param pollution |
| [graphql/](graphql/) | [introspection_queries.md](graphql/introspection_queries.md) | Full introspection, bypass, batching, nested DoS |
| | [graphql_injection.md](graphql/graphql_injection.md) | SQLi/NoSQLi/SSRF/XSS/command injection via GraphQL |
| [ssrf/](ssrf/) | [api_ssrf_payloads.md](ssrf/api_ssrf_payloads.md) | Cloud metadata, internal services, protocol smuggling, filter bypass |
| [injection/](injection/) | [nosql_injection.md](injection/nosql_injection.md) | MongoDB operators, $where, CouchDB, Cassandra, Redis |
| [wordlists/](wordlists/) | [api_endpoints.txt](wordlists/api_endpoints.txt) | 200+ API endpoint paths for ffuf/dirsearch discovery |
| | [api_params.txt](wordlists/api_params.txt) | 100+ parameter names for hidden param fuzzing |
| [testing-steps/](testing-steps/) | [api_checklist.md](testing-steps/api_checklist.md) | OWASP API Top 10 checklist with curl commands |

## OWASP API Top 10 Mapping

| # | Category | Folder | Severity |
|---|----------|--------|----------|
| API1 | Broken Object Level Authorization | [bola/](bola/) | CRITICAL |
| API2 | Broken Authentication | [broken-auth/](broken-auth/) | CRITICAL |
| API3 | Broken Object Property Level Authorization | [mass-assignment/](mass-assignment/) | HIGH |
| API4 | Unrestricted Resource Consumption | [rate-limit/](rate-limit/) | MEDIUM |
| API5 | Broken Function Level Authorization | [bfla/](bfla/) | HIGH |
| API6 | Unrestricted Access to Sensitive Flows | [mass-assignment/](mass-assignment/) | HIGH |
| API7 | Server Side Request Forgery | [ssrf/](ssrf/) | HIGH |
| API8 | Security Misconfiguration | [testing-steps/](testing-steps/) | MEDIUM |
| API9 | Improper Inventory Management | [wordlists/](wordlists/) | MEDIUM |
| API10 | Unsafe Consumption of APIs | [testing-steps/](testing-steps/) | HIGH |

## Quick Start

```bash
# Decode a JWT
python -I broken-auth/jwt_attacks.py --token <jwt> --attack decode

# Brute-force JWT secret
python -I broken-auth/jwt_attacks.py --token <jwt> --attack bruteforce --wordlist broken-auth/jwt_common_secrets.txt

# Fuzz API endpoints
ffuf -u https://api.target.com/FUZZ -w wordlists/api_endpoints.txt -mc 200,301,302,403

# Discover hidden parameters
arjun -u https://api.target.com/api/v1/users -w wordlists/api_params.txt

# GraphQL introspection
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name kind}}}"}'
```

## Tools

| Tool | Purpose |
|------|---------|
| Burp Suite | HTTP proxy + scanner |
| Postman | API testing and collections |
| ffuf / feroxbuster | Endpoint fuzzing |
| jwt_tool / jwt_attacks.py | JWT manipulation and attacks |
| Arjun | Hidden parameter discovery |
| Kiterunner | API endpoint discovery |
| InQL (Burp) | GraphQL introspection scanner |
| graphw00f | GraphQL server fingerprinting |
| nuclei | Template-based API scanning |
