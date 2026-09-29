#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Citrix NetScaler CVE-2026-88772 memory corruption exposure."""

import re
import ssl

from requests.adapters import HTTPAdapter

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Citrix NetScaler CVE-2026-88772 Detect",
        "description": (
            "Detects Citrix NetScaler ADC/Gateway builds likely affected by "
            "CVE-2026-88772 (memory buffer restriction flaw enabling RCE/DoS). "
            "Confirms NetScaler presence and pre-CTX697096 firmware where exposed."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-88772"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-88772",
            "https://support.citrix.com/s/article/CTX697096",
        ],
        "tags": [
            "web",
            "scanner",
            "citrix",
            "netscaler",
            "adc",
            "memory-corruption",
            "rce",
            "cve-2026-88772",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.15,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["citrix", "netscaler", "adc"],
            },
            "chain": {
                "suggested_followups": [
                    "scanner/http/citrix_netscaler_cve_2026_88771_detect",
                ],
            },
        },
    }

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
        response = self.http_request(method="GET", path="/vpn/index.html", allow_redirects=True)
        if not response:
            return False
        body = response.text or ""
        blob = body.lower()
        if not any(token in blob for token in ("netscaler", "citrix", "gateway", "cvpn")):
            return False
        build = self._parse_build(body)
        affected = self._build_affected(build)
        if affected is False:
            return False
        if affected is True:
            self.set_info(
                severity="high",
                cve="CVE-2026-88772",
                reason="NetScaler build appears pre-CTX697096 (CVE-2026-88772 exposure)",
                build=build,
            )
            return True
        self.set_info(
            severity="medium",
            cve="CVE-2026-88772",
            reason="NetScaler gateway detected (build unknown — verify patch level manually)",
            build=build or "unknown",
        )
        return True
