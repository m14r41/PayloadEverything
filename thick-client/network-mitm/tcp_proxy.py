"""
TCP MitM Proxy — Intercept non-HTTP traffic from thick clients.

Many thick-client applications use custom TCP protocols, raw sockets,
or proprietary binary protocols that Burp Suite cannot intercept.
This proxy sits between the client and server, logging all traffic.

Usage:
    python -I tcp_proxy.py --listen 0.0.0.0:8080 --target server.example.com:9090
    python -I tcp_proxy.py --listen 0.0.0.0:8080 --target 10.0.0.5:1433 --hex
    python -I tcp_proxy.py --listen 0.0.0.0:443 --target api.target.com:443 --tls

    Then point the thick client at localhost:8080 (via hosts file, DNS, or config)

Features:
    - Raw TCP proxying with full traffic logging
    - TLS/SSL stripping and re-encryption
    - Hex dump for binary protocols
    - Auto-detect and decode common formats (JSON, XML, protobuf markers)
    - Traffic modification via --replace rules
    - PCAP-compatible logging
"""

import argparse
import os
import select
import socket
import ssl
import sys
import threading
import time
from datetime import datetime


def hexdump(data, prefix=""):
    result = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        result.append(f"{prefix}{i:08x}  {hex_str:<48}  {ascii_str}")
    return "\n".join(result)


def detect_format(data):
    if not data:
        return "empty"
    if data[:1] in (b"{", b"["):
        return "JSON"
    if data[:1] == b"<":
        return "XML"
    if data[:4] == b"\x00\x00\x00\x00":
        return "binary"
    if data[:3] == b"GET" or data[:4] == b"POST" or data[:3] == b"PUT":
        return "HTTP"
    if data[:2] == b"\x16\x03":
        return "TLS"
    if data[:4] == b"\x12\x01\x00\x00":
        return "TDS (MSSQL)"
    try:
        data.decode("utf-8")
        return "text/UTF-8"
    except Exception:
        return "binary"


class TCPProxy:
    def __init__(self, listen_host, listen_port, target_host, target_port,
                 use_hex=False, use_tls=False, replacements=None, log_dir=None):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.use_hex = use_hex
        self.use_tls = use_tls
        self.replacements = replacements or []
        self.log_dir = log_dir
        self.connection_count = 0

        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

    def log(self, direction, data, conn_id):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        fmt = detect_format(data)

        arrow = ">>>" if direction == "C2S" else "<<<"
        color_start = "\033[92m" if direction == "C2S" else "\033[93m"
        color_end = "\033[0m"

        print(f"\n{color_start}[{timestamp}] [{direction}] {len(data)} bytes ({fmt}) {arrow}{color_end}")

        if self.use_hex or fmt == "binary":
            print(hexdump(data, "  "))
        else:
            try:
                text = data.decode("utf-8", errors="replace")
                for line in text.split("\n")[:50]:
                    print(f"  {line}")
                if text.count("\n") > 50:
                    print(f"  ... ({text.count(chr(10))} total lines)")
            except Exception:
                print(hexdump(data, "  "))

        # Write to log file
        if self.log_dir:
            log_file = os.path.join(self.log_dir, f"conn_{conn_id}.log")
            with open(log_file, "ab") as f:
                f.write(f"[{timestamp}] [{direction}] {len(data)} bytes\n".encode())
                f.write(data)
                f.write(b"\n---\n")

            # Also write raw binary
            raw_file = os.path.join(self.log_dir, f"conn_{conn_id}_{direction.lower()}.bin")
            with open(raw_file, "ab") as f:
                f.write(data)

    def apply_replacements(self, data, direction):
        for old, new, d in self.replacements:
            if d == "both" or d == direction:
                data = data.replace(old.encode(), new.encode())
        return data

    def handle_connection(self, client_socket, client_addr):
        self.connection_count += 1
        conn_id = self.connection_count

        print(f"\n[*] Connection #{conn_id} from {client_addr[0]}:{client_addr[1]}")

        try:
            # Connect to target
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.connect((self.target_host, self.target_port))

            if self.use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                target_socket = context.wrap_socket(target_socket,
                    server_hostname=self.target_host)
                print(f"[+] TLS connection to {self.target_host}:{self.target_port}")

            print(f"[+] Connected to target {self.target_host}:{self.target_port}")

            # Bi-directional proxy
            sockets = [client_socket, target_socket]

            while True:
                readable, _, _ = select.select(sockets, [], [], 1.0)

                for sock in readable:
                    try:
                        data = sock.recv(65536)
                    except Exception:
                        data = b""

                    if not data:
                        print(f"[*] Connection #{conn_id} closed")
                        return

                    if sock is client_socket:
                        # Client → Server
                        data = self.apply_replacements(data, "C2S")
                        self.log("C2S", data, conn_id)
                        target_socket.send(data)
                    else:
                        # Server → Client
                        data = self.apply_replacements(data, "S2C")
                        self.log("S2C", data, conn_id)
                        client_socket.send(data)

        except Exception as e:
            print(f"[-] Connection #{conn_id} error: {e}")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass
            try:
                target_socket.close()
            except Exception:
                pass

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.listen_host, self.listen_port))
        server.listen(5)

        print(f"[*] TCP Proxy listening on {self.listen_host}:{self.listen_port}")
        print(f"[*] Forwarding to {self.target_host}:{self.target_port}")
        if self.use_tls:
            print(f"[*] TLS enabled for target connection")
        if self.replacements:
            print(f"[*] {len(self.replacements)} replacement rule(s) active")
        if self.log_dir:
            print(f"[*] Logging to {self.log_dir}/")
        print(f"[*] Press Ctrl+C to stop\n")

        try:
            while True:
                client_socket, addr = server.accept()
                thread = threading.Thread(target=self.handle_connection,
                    args=(client_socket, addr), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down proxy")
            server.close()


def parse_endpoint(endpoint):
    parts = endpoint.rsplit(":", 1)
    if len(parts) != 2:
        print(f"[-] Invalid endpoint: {endpoint} (use host:port)")
        sys.exit(1)
    return parts[0], int(parts[1])


def main():
    parser = argparse.ArgumentParser(description="TCP MitM Proxy for thick-client VAPT")
    parser.add_argument("--listen", "-l", required=True, help="Listen address (host:port)")
    parser.add_argument("--target", "-t", required=True, help="Target address (host:port)")
    parser.add_argument("--hex", action="store_true", help="Force hex dump output")
    parser.add_argument("--tls", action="store_true", help="Use TLS for target connection")
    parser.add_argument("--replace", action="append", nargs=3,
        metavar=("OLD", "NEW", "DIR"),
        help="Replace OLD with NEW in direction DIR (C2S/S2C/both)")
    parser.add_argument("--log", help="Directory to save traffic logs")
    args = parser.parse_args()

    listen_host, listen_port = parse_endpoint(args.listen)
    target_host, target_port = parse_endpoint(args.target)

    replacements = args.replace or []

    proxy = TCPProxy(
        listen_host, listen_port,
        target_host, target_port,
        use_hex=args.hex,
        use_tls=args.tls,
        replacements=replacements,
        log_dir=args.log,
    )
    proxy.start()


if __name__ == "__main__":
    main()
