#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Citrix NetScaler CVE-2026-19490 SAML authentication bypass exposure."""

import re
import ssl

from requests.adapters import HTTPAdapter

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Citrix NetScaler CVE-2026-19490 Detect",
        "description": (
            "Detects Citrix NetScaler ADC/Gateway deployments likely exposed to "
            "CVE-2026-19490 (SAML alternate-path authentication bypass). Requires "
            "Gateway/AAA virtual server usage; flags affected 13.1/14.1 builds "
            "before 13.1-63.21 / 14.1-73.32 and reachable SAML endpoints."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-19490"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-19490",
            "https://support.citrix.com/s/article/CTX694791",
        ],
        "tags": [
            "web",
            "scanner",
            "citrix",
            "netscaler",
            "adc",
            "gateway",
            "saml",
            "auth-bypass",
            "cve-2026-19490",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.25,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["citrix", "netscaler", "adc"],
                "endpoint_pattern_any": ["/vpn/", "/saml/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "SAML alternate path"},
                ],
                "suggested_followups": [
                    "scanner/http/netscaler_gateway_detect",
                    "scanner/http/citrix_netscaler_cve_2026_88771_detect",
                ],
            },
        },
    }

    saml_paths = OptString(
        "/saml/login,/cgi/samlauth,/vpn/index.html",
        "Comma-separated SAML or gateway probe paths",
        False,
        advanced=True,
    )

    _BUILD_RE = re.compile(
        r"(?:NS(?:13|14)\.\d[-\w.]+|NetScaler\s+\d{2}\.\d[-\w.]*)",
        re.IGNORECASE,
    )

    def _configure_netscaler_ssl(self):
        class _NetscalerSSLAdapter(HTTPAdapter):
            def init_poolmanager(self, *args, **kwargs):
                ctx = ssl.create_default_context()
                ctx.set_ciphers("DEFAULT@SECLEVEL=1")
                ctx.check_hostname = False
                kwargs["ssl_context"] = ctx
                return super().init_poolmanager(*args, **kwargs)

        self.session.mount("https://", _NetscalerSSLAdapter())

    @staticmethod
    def _parse_build(text: str) -> str:
        match = Module._BUILD_RE.search(text or "")
        return match.group(0) if match else ""

    @staticmethod
    def _build_affected(build: str) -> bool | None:
        if not build:
            return None
        normalized = build.upper().replace("NETSCALER", "").strip()
        match = re.search(r"(13|14)\.(\d+)[-\s]?([\d.]+)?", normalized)
        if not match:
            return None
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = match.group(3) or "0"
        try:
            hotfix = float(patch.split("-")[0])
        except ValueError:
            hotfix = 0.0
        if major == 14 and minor == 1:
            return hotfix < 73.32
        if major == 13 and minor == 1:
            return hotfix < 63.21
        return None

    def run(self):
        try:
            self._configure_netscaler_ssl()
        except Exception:
            pass

        gateway = self.http_request(method="GET", path="/vpn/index.html", allow_redirects=True)
        if not gateway:
            return False
        body = gateway.text or ""
        blob = body.lower()
        if not any(token in blob for token in ("netscaler", "citrix", "gateway", "cvpn")):
            return False

        build = self._parse_build(body)
        saml_reachable = False
        for path in str(self.saml_paths or "").split(","):
            path = path.strip()
            if not path:
                continue
            response = self.http_request(method="GET", path=path, allow_redirects=False)
            if not response:
                continue
            code = int(response.status_code or 0)
            text = (response.text or "").lower()
            if code in (200, 302, 401, 403) and (
                "saml" in path.lower() or "saml" in text or "authnrequest" in text
            ):
                saml_reachable = True
                build = build or self._parse_build(response.text or "")

        affected = self._build_affected(build)
        if affected is False:
            return False
        if affected is True and saml_reachable:
            self.set_info(
                severity="critical",
                cve="CVE-2026-19490",
                reason="Affected NetScaler build with reachable SAML/gateway surface",
                build=build,
            )
            return True
        if saml_reachable and affected is None:
            self.set_info(
                severity="high",
                cve="CVE-2026-19490",
                reason="NetScaler SAML/gateway surface reachable (build unknown)",
                build=build or "unknown",
            )
            return True
        return False
