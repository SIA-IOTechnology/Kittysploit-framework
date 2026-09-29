#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Adobe Campaign Classic CVE-2026-83660 / CVE-2026-89276 exposure."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Adobe Campaign Classic CVE-2026-83660 Detect",
        "description": (
            "Detects Adobe Campaign Classic (ACC) instances likely affected by "
            "CVE-2026-83660 (unauthenticated SSRF / privilege escalation) and "
            "CVE-2026-89276 (low-privilege code injection). Fingerprints ACC "
            "JSP surfaces and parses build numbers from /r/test against the "
            "APSB26-142 fixed build 7.4.4.9402."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-83660", "CVE-2026-89276"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-83660",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-89276",
            "https://helpx.adobe.com/security/products/campaign/apsb26-142.html",
        ],
        "tags": [
            "web",
            "scanner",
            "adobe",
            "campaign",
            "acc",
            "ssrf",
            "code-injection",
            "cve-2026-83660",
            "cve-2026-89276",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.15,
            "value": 1.0,
            "requires": {
                "endpoint_pattern_any": ["/nl/jsp/", "/r/test"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "ssrf", "from_detail": "ACC server-side request"},
                    {"capability": "code_injection", "from_detail": "ACC workflow scripting"},
                ],
            },
        },
    }

    port = OptPort(8080, "Adobe Campaign HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)

    _BUILD_RE = re.compile(
        r"(?:build|version|7\.[\d.]+)[^\d]{0,16}(\d{3,5})",
        re.IGNORECASE,
    )
    _FIXED_BUILD = 9402

    @staticmethod
    def _parse_build(text: str) -> int | None:
        if not text:
            return None
        for pattern in (
            Module._BUILD_RE,
            re.compile(r"7\.4\.4[^\d]{0,8}(\d{4})", re.IGNORECASE),
            re.compile(r"\b(94\d{2})\b"),
        ):
            match = pattern.search(text)
            if match:
                try:
                    return int(match.group(1))
                except ValueError:
                    continue
        return None

    def _acc_present(self) -> tuple[bool, str]:
        for path in ("/nl/jsp/logon.jsp", "/nl/jsp/soaprouter.jsp", "/"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response:
                continue
            body = response.text or ""
            headers = " ".join(f"{k}:{v}" for k, v in (response.headers or {}).items())
            blob = f"{body}\n{headers}".lower()
            if any(
                token in blob
                for token in (
                    "adobe campaign",
                    "campaign classic",
                    "nlserver",
                    "setup-client-7.",
                    "/nl/jsp/",
                )
            ):
                return True, body
        return False, ""

    def run(self):
        present, body = self._acc_present()
        if not present:
            return False

        build = self._parse_build(body)
        test_resp = self.http_request(method="GET", path="/r/test", allow_redirects=False)
        if test_resp and int(test_resp.status_code or 0) in (200, 401, 403):
            build = build or self._parse_build(test_resp.text or "")

        if build is not None and build >= self._FIXED_BUILD:
            return False

        cve_note = "CVE-2026-83660 (SSRF) and CVE-2026-89276 (code injection)"
        if build is not None and build < self._FIXED_BUILD:
            reason = (
                f"Adobe Campaign Classic build {build} appears pre-APSB26-142 "
                f"({cve_note})"
            )
            severity = "critical"
        else:
            reason = (
                f"Adobe Campaign Classic detected ({cve_note}); build unknown — "
                "verify >= 7.4.4.9402 manually"
            )
            severity = "high"

        self.set_info(
            severity=severity,
            cve="CVE-2026-83660",
            reason=reason,
            build=str(build) if build is not None else "unknown",
            path="/nl/jsp/logon.jsp",
        )
        return True
