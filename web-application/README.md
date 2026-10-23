# Web Application Payloads

> **Status**: Active

Payloads and PoC files for web application security assessments, mapped to the [OWASP Top 10](https://owasp.org/www-project-top-ten/).

## Structure

| Folder | File | Description |
|--------|------|-------------|
| [xss/](xss/) | [xss_payloads.txt](xss/xss_payloads.txt) | 80+ XSS payloads — basic, event handlers, filter bypass, WAF bypass, DOM, CSP, blind, stored |
| [sqli/](sqli/) | [sqli_payloads.md](sqli/sqli_payloads.md) | 60+ SQLi payloads — UNION, error, blind, time-based, auth bypass, WAF bypass, NoSQL |
| [ssrf/](ssrf/) | [ssrf_payloads.md](ssrf/ssrf_payloads.md) | Cloud metadata (AWS/GCP/Azure/DO/Alibaba/K8s), protocol smuggling, IP bypass |
| [ssti/](ssti/) | [ssti_payloads.md](ssti/ssti_payloads.md) | 12 engines — Jinja2, Twig, Freemarker, Velocity, ERB, Pebble, Smarty, Mako, Handlebars, Thymeleaf, EJS, Nunjucks |
| [file-upload/](file-upload/) | [webshells/cmd.php](file-upload/webshells/cmd.php), [cmd.aspx](file-upload/webshells/cmd.aspx), [cmd.jsp](file-upload/webshells/cmd.jsp), [cmd.py](file-upload/webshells/cmd.py) | Web shells for PHP, ASPX, JSP, Python |
| | [bypass_tips.md](file-upload/bypass_tips.md) | Extension, content-type, magic byte bypass, .htaccess, web.config, polyglots, race condition |
| [lfi/](lfi/) | [lfi_payloads.md](lfi/lfi_payloads.md) | Path traversal, encoding bypass, PHP wrappers (filter/input/data/expect/zip/phar), log poisoning |
| [command-injection/](command-injection/) | [cmdi_payloads.md](command-injection/cmdi_payloads.md) | OS command injection (Linux/Windows), blind exfil, filter bypass, parameter pollution |
| [auth-bypass/](auth-bypass/) | [jwt_attacks.py](auth-bypass/jwt_attacks.py) | JWT toolkit — none alg, alg confusion, brute-force, claim tamper, kid injection, jku spoof |
| | [jwt_common_secrets.txt](auth-bypass/jwt_common_secrets.txt) | 70+ weak JWT secrets wordlist for brute-force |
| [cors/](cors/) | [cors_poc.html](cors/cors_poc.html) | Interactive CORS PoC — reflected origin, null origin, wildcard, subdomain trust |
| [open-redirect/](open-redirect/) | [redirect_payloads.md](open-redirect/redirect_payloads.md) | 40+ redirect payloads — protocol-relative, encoding, @-trick, null byte, JS protocol |
| [deserialization/](deserialization/) | [java_deserialization.md](deserialization/java_deserialization.md) | ysoserial commands, ysoserial.net, JNDI/Log4Shell, Python pickle, PHP/phpggc |
| [xxe/](xxe/) | [xxe_payloads.txt](xxe/xxe_payloads.txt) | File read, SSRF, blind OOB, error-based, SOAP, SVG, XLSX/DOCX, XInclude, CDATA |

## OWASP Top 10 Mapping

| OWASP Category                        | Folders                                      |
|---------------------------------------|----------------------------------------------|
| A01 Broken Access Control             | `auth-bypass/`, `cors/`, `open-redirect/`    |
| A02 Cryptographic Failures            | `auth-bypass/` (JWT weak secrets)            |
| A03 Injection                         | `sqli/`, `xss/`, `ssti/`, `command-injection/`, `xxe/` |
| A04 Insecure Design                   | `cors/`, `open-redirect/`                    |
| A05 Security Misconfiguration         | `cors/`, `xxe/`, `file-upload/`              |
| A06 Vulnerable Components             | `deserialization/`                            |
| A07 Auth Failures                     | `auth-bypass/`                               |
| A08 Data Integrity Failures           | `deserialization/`, `auth-bypass/` (JWT)     |
| A09 Logging Failures                  | `lfi/` (log poisoning)                       |
| A10 SSRF                              | `ssrf/`, `xxe/`                              |

## Quick Start

1. **XSS** — Paste from [xss_payloads.txt](xss/xss_payloads.txt) into input fields, URL params, headers
2. **SQLi** — Start with detection probes from [sqli_payloads.md](sqli/sqli_payloads.md), escalate to UNION/blind
3. **SSRF** — Replace URL/host params with entries from [ssrf_payloads.md](ssrf/ssrf_payloads.md)
4. **SSTI** — Inject detection polyglots from [ssti_payloads.md](ssti/ssti_payloads.md), identify engine, escalate
5. **File Upload** — Upload shells from [webshells/](file-upload/webshells/), use bypass techniques from [bypass_tips.md](file-upload/bypass_tips.md)
6. **LFI** — Try path traversal from [lfi_payloads.md](lfi/lfi_payloads.md), escalate with PHP wrappers
7. **Command Injection** — Inject separators from [cmdi_payloads.md](command-injection/cmdi_payloads.md) into OS-command parameters
8. **JWT** — Run `python -I jwt_attacks.py brute -t <token>` to crack weak secrets, then tamper claims
9. **CORS** — Open [cors_poc.html](cors/cors_poc.html) in browser, point at target endpoint
10. **XXE** — Inject DTD entities from [xxe_payloads.txt](xxe/xxe_payloads.txt) into XML endpoints / file uploads

## Contributing

Each subfolder contains payload files organized by technique. To add new categories:
- Create a folder matching the attack vector name
- Add `.txt` payload files, generator scripts, or PoC HTML
- Keep payloads practical and real-world tested
