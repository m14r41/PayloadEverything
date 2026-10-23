/*
 * YARA Rules for Thick-Client Memory Analysis
 *
 * Scan process memory dumps for credentials, tokens, keys, and secrets.
 *
 * Usage:
 *   yara credential_patterns.yar process_dump.dmp
 *   yara -s credential_patterns.yar *.dmp   (show matching strings)
 *
 * Create dump first:
 *   procdump -ma <PID> dump.dmp
 *   .\dump_process_memory.ps1 -ProcessName "TargetApp"
 */

rule JWT_Token
{
    meta:
        description = "JSON Web Token in memory"
        severity = "HIGH"
    strings:
        $jwt = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/
    condition:
        $jwt
}

rule Plaintext_Password_Field
{
    meta:
        description = "Password field with value in plaintext"
        severity = "CRITICAL"
    strings:
        $p1 = "password=" ascii wide nocase
        $p2 = "password\":" ascii wide nocase
        $p3 = "passwd=" ascii wide nocase
        $p4 = "pwd=" ascii wide nocase
        $p5 = "\"password\":\"" ascii wide nocase
        $p6 = "<password>" ascii wide nocase
    condition:
        any of them
}

rule Connection_String
{
    meta:
        description = "Database connection string with credentials"
        severity = "CRITICAL"
    strings:
        $cs1 = "Server=" ascii wide nocase
        $cs2 = "Data Source=" ascii wide nocase
        $cs3 = "Provider=" ascii wide nocase
        $cs4 = "jdbc:" ascii wide nocase
        $cs5 = "mongodb://" ascii wide
        $cs6 = "postgresql://" ascii wide
        $cs7 = "mysql://" ascii wide
        $pwd = "Password=" ascii wide nocase
        $uid = "User ID=" ascii wide nocase
    condition:
        ($pwd or $uid) and any of ($cs*)
}

rule OAuth_Token
{
    meta:
        description = "OAuth access or refresh token"
        severity = "HIGH"
    strings:
        $at = "access_token" ascii wide nocase
        $rt = "refresh_token" ascii wide nocase
        $bt = /Bearer [A-Za-z0-9_\-\.]{20,}/ ascii wide
    condition:
        any of them
}

rule AWS_Credentials
{
    meta:
        description = "AWS access key in memory"
        severity = "CRITICAL"
    strings:
        $key = /AKIA[0-9A-Z]{16}/ ascii wide
        $secret = "aws_secret_access_key" ascii wide nocase
        $session = "aws_session_token" ascii wide nocase
    condition:
        any of them
}

rule Private_Key_Material
{
    meta:
        description = "Private key in memory"
        severity = "CRITICAL"
    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----" ascii wide
        $ec = "-----BEGIN EC PRIVATE KEY-----" ascii wide
        $pk = "-----BEGIN PRIVATE KEY-----" ascii wide
        $enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----" ascii wide
        $pfx = { 30 82 ?? ?? 02 01 03 30 82 }
    condition:
        any of them
}

rule API_Key_Pattern
{
    meta:
        description = "API key or secret in memory"
        severity = "HIGH"
    strings:
        $ak1 = "api_key" ascii wide nocase
        $ak2 = "apikey" ascii wide nocase
        $ak3 = "api-key" ascii wide nocase
        $sk1 = "secret_key" ascii wide nocase
        $sk2 = "client_secret" ascii wide nocase
        $gh = /gh[ps]_[A-Za-z0-9]{36}/ ascii
        $slack = /xox[baprs]-[A-Za-z0-9\-]{10,}/ ascii
    condition:
        any of them
}

rule Session_Cookie
{
    meta:
        description = "Session cookie value in memory"
        severity = "HIGH"
    strings:
        $php = /PHPSESSID=[A-Za-z0-9]{26,}/ ascii wide
        $java = /JSESSIONID=[A-Za-z0-9]{32,}/ ascii wide
        $asp = /ASP\.NET_SessionId=[A-Za-z0-9]{24,}/ ascii wide
        $node = /connect\.sid=s%3A[A-Za-z0-9%\-\.]{20,}/ ascii wide
        $set = "Set-Cookie:" ascii wide nocase
    condition:
        any of ($php, $java, $asp, $node) or ($set and any of ($php, $java, $asp, $node))
}

rule Encryption_Key_Hex
{
    meta:
        description = "Possible encryption key (hex string)"
        severity = "MEDIUM"
    strings:
        $aes128 = /[Kk]ey["'=: ]+[0-9a-fA-F]{32}/ ascii wide
        $aes256 = /[Kk]ey["'=: ]+[0-9a-fA-F]{64}/ ascii wide
        $iv = /[Ii][Vv]["'=: ]+[0-9a-fA-F]{32}/ ascii wide
    condition:
        any of them
}

rule NTLM_Hash
{
    meta:
        description = "NTLM hash in memory"
        severity = "CRITICAL"
    strings:
        $ntlm = /[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}/ ascii
        $ntlm_resp = { 4e 54 4c 4d 53 53 50 00 }
    condition:
        any of them
}

rule Base64_Credentials
{
    meta:
        description = "Base64-encoded Basic auth or credentials"
        severity = "HIGH"
    strings:
        $basic = /Basic [A-Za-z0-9+\/=]{10,}/ ascii wide
        $b64_user = /dXNlcm5hbWU/ ascii wide
        $b64_pass = /cGFzc3dvcmQ/ ascii wide
        $b64_admin = /YWRtaW4/ ascii wide
    condition:
        any of them
}

rule Cleartext_Protocol
{
    meta:
        description = "Cleartext protocol communication in memory"
        severity = "MEDIUM"
    strings:
        $http = "http://" ascii wide
        $ftp = /ftp:\/\/[^\s]+:[^\s]+@/ ascii wide
        $smtp = "AUTH PLAIN" ascii wide
        $ldap = /ldap:\/\/[^\s]*/ ascii wide nocase
    condition:
        $ftp or $smtp or ($http and ($ldap))
}
