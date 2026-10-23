# BloodHound Custom Cypher Queries

Custom Neo4j Cypher queries for BloodHound during Active Directory penetration tests.

**MITRE ATT&CK**: T1087.002

## Domain Admins

```cypher
// All Domain Admin members (including nested groups)
MATCH p=(u)-[:MemberOf*1..]->(g:Group)
WHERE g.name =~ '(?i)domain admins@.*'
RETURN p

// Shortest path to Domain Admin from owned principals
MATCH p=shortestPath((u {owned:true})-[*1..]->(g:Group))
WHERE g.name =~ '(?i)domain admins@.*'
RETURN p

// Users that can reach Domain Admin in 3 hops or fewer
MATCH p=shortestPath((u:User)-[*1..3]->(g:Group))
WHERE g.name =~ '(?i)domain admins@.*' AND NOT u.name =~ '(?i).*admin.*'
RETURN p
```

## Kerberoasting Targets

```cypher
// All Kerberoastable users with admin count
MATCH (u:User)
WHERE u.hasspn = true
RETURN u.name, u.admincount, u.description, u.enabled
ORDER BY u.admincount DESC

// Kerberoastable users with path to DA
MATCH (u:User {hasspn:true}), (g:Group)
WHERE g.name =~ '(?i)domain admins@.*'
MATCH p=shortestPath((u)-[*1..]->(g))
RETURN p

// High-value Kerberoastable users (member of privileged groups)
MATCH (u:User {hasspn:true})-[:MemberOf*1..]->(g:Group)
WHERE g.highvalue = true
RETURN u.name, g.name
```

## AS-REP Roastable

```cypher
// Users without Kerberos pre-authentication
MATCH (u:User)
WHERE u.dontreqpreauth = true
RETURN u.name, u.enabled, u.description

// AS-REP Roastable users with paths to high-value targets
MATCH (u:User {dontreqpreauth:true}), (g:Group {highvalue:true})
MATCH p=shortestPath((u)-[*1..]->(g))
RETURN p
```

## Delegation

```cypher
// Unconstrained delegation computers (exclude DCs)
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name =~ '(?i).*dc.*'
RETURN c.name, c.operatingsystem

// Constrained delegation objects
MATCH (c) WHERE c.allowedtodelegate IS NOT NULL
RETURN c.name, c.allowedtodelegate

// Resource-based constrained delegation
MATCH p=(c1)-[:AllowedToAct]->(c2)
RETURN p
```

## ACL Abuse Paths

```cypher
// Principals with GenericAll on users
MATCH p=(u)-[:GenericAll]->(t:User)
WHERE NOT u.name =~ '(?i).*admin.*'
RETURN p

// WriteDacl on domain object (potential DCSync)
MATCH p=(u)-[:WriteDacl|WriteOwner|GenericAll*1..]->(d:Domain)
RETURN p

// ForceChangePassword rights
MATCH p=(u)-[:ForceChangePassword]->(t:User)
RETURN p

// Principals that can add members to groups
MATCH p=(u)-[:AddMember|GenericAll|GenericWrite]->(g:Group)
WHERE g.highvalue = true
RETURN p

// Full ACL abuse chain from owned to DA
MATCH p=shortestPath((u {owned:true})-[:GenericAll|GenericWrite|WriteOwner|WriteDacl|AddMember|ForceChangePassword|Owns*1..]->(g:Group))
WHERE g.name =~ '(?i)domain admins@.*'
RETURN p
```

## Credential Paths

```cypher
// Computers where Domain Admins have sessions
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.name =~ '(?i)domain admins@.*'
MATCH (c:Computer)-[:HasSession]->(u)
RETURN u.name, c.name

// Derivative local admin paths
MATCH p=shortestPath((u:User {owned:true})-[:AdminTo|HasSession|MemberOf*1..]->(c:Computer))
WHERE NOT u.name =~ '(?i).*admin.*'
RETURN p

// Users with local admin on multiple machines
MATCH (u:User)-[:AdminTo]->(c:Computer)
WITH u, count(c) AS adminCount
WHERE adminCount > 5
RETURN u.name, adminCount
ORDER BY adminCount DESC
```

## GPO Abuse

```cypher
// GPOs that affect Domain Admins or DCs
MATCH p=(g:GPO)-[:GpLink]->(ou:OU)-[:Contains*1..]->(t)
WHERE t.highvalue = true
RETURN p

// Users with GPO edit rights
MATCH (u:User)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl]->(g:GPO)
RETURN u.name, g.name

// GPO to computer paths
MATCH p=(g:GPO)-[:GpLink]->(ou:OU)-[:Contains*1..]->(c:Computer)
RETURN p
```

## Trust Relationships

```cypher
// All domain trusts
MATCH p=(d1:Domain)-[:TrustedBy]->(d2:Domain)
RETURN p

// Foreign group membership
MATCH p=(u)-[:MemberOf]->(g:Group)
WHERE u.domain <> g.domain
RETURN p

// SID History abuse paths
MATCH (u) WHERE u.sidhistory <> []
RETURN u.name, u.sidhistory
```

## Post-Compromise / Situational Awareness

```cypher
// All computers running outdated OS
MATCH (c:Computer)
WHERE c.operatingsystem =~ '(?i).*(2008|2003|2000|xp|vista|7).*'
RETURN c.name, c.operatingsystem

// Enabled users who never logged in
MATCH (u:User)
WHERE u.enabled = true AND u.lastlogontimestamp = -1
RETURN u.name, u.description

// Users with password never expires
MATCH (u:User {pwdneverexpires:true, enabled:true})
RETURN u.name, u.description

// Computers with LAPS not enabled
MATCH (c:Computer)
WHERE c.haslaps = false
RETURN c.name, c.operatingsystem

// Find all owned principals and their paths
MATCH p=(u {owned:true})-[*1..3]->(t)
WHERE t.highvalue = true
RETURN p
```

## Data Collection Commands

```cmd
:: SharpHound collection
SharpHound.exe -c All --zipfilename output.zip
SharpHound.exe -c All --ldapusername user --ldappassword pass --domaincontroller dc01
SharpHound.exe -c Session --loop --loopduration 02:00:00

:: AzureHound (Azure AD)
azurehound -r <refresh_token> list --tenant <tenant_id> -o output.json
```
