#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect ConnectWise ScreenConnect client CVE-2026-84869 (pre-26.6.5)."""

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "ConnectWise ScreenConnect CVE-2026-84869 Detect",
        "description": (
            "Detects ScreenConnect server deployments likely serving vulnerable client "
            "builds before 26.6.5.9742 (CVE-2026-84869): guest file transfer without "
            "Host confirmation during active sessions. Parses version markers from "
            "Login/Host pages and flags releases below 26.6.5."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-84869"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-84869",
            "https://www.connectwise.com/company/trust/security-bulletins/2026-09-08-screenconnect-bulletin",
        ],
        "tags": [
            "web",
            "scanner",
            "screenconnect",
            "connectwise",
            "file-transfer",
            "cve-2026-84869",
            "kev",
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
            "noise": 0.2,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["screenconnect", "connectwise"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce_surface", "from_detail": "unauth file transfer"},
                ],
                "suggested_followups": [
                    "scanner/http/connectwise_screenconnect_cve_2024_1709_detect",
                ],
            },
        },
    }

    _VERSION_RE = re.compile(
        r"(?:ScreenConnect|productVersion|Version)[^0-9]{0,24}(\d+\.\d+\.\d+(?:\.\d+)?)",
        re.IGNORECASE,
    )

    @staticmethod
    def _parse_version(text: str) -> Optional[Tuple[int, int, int, int]]:
        match = Module._VERSION_RE.search(text or "")
        if not match:
            return None
        parts = match.group(1).split(".")
        while len(parts) < 4:
            parts.append("0")
        try:
            return tuple(int(x) for x in parts[:4])  # type: ignore[return-value]
        except ValueError:
            return None

    @staticmethod
    def _below_fixed(version: Tuple[int, int, int, int]) -> bool:
        major, minor, patch, build = version
        if major != 26:
            return major < 26
        if minor < 6:
            return True
        if minor > 6:
            return False
        if patch < 5:
            return True
        if patch > 5:
            return False
        return build < 9742

    def _screenconnect_blob(self) -> str:
        chunks = []
        for path in ("/Login", "/Host", "/"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response:
                continue
            chunks.append(response.text or "")
            if any(token in (response.text or "") for token in ("ScreenConnect", "ConnectWise")):
                break
        return "\n".join(chunks)

    def run(self):
        blob = self._screenconnect_blob()
        if "ScreenConnect" not in blob and "ConnectWise" not in blob:
            return False
        version = self._parse_version(blob)
        if not version:
            self.set_info(
                severity="medium",
                cve="CVE-2026-84869",
                reason="ScreenConnect detected; version unknown — verify client build >= 26.6.5.9742",
            )
            return True
        version_str = ".".join(str(x) for x in version)
        if self._below_fixed(version):
            self.set_info(
                severity="critical",
                cve="CVE-2026-84869",
                reason=f"ScreenConnect {version_str} is below fixed 26.6.5.9742",
                version=version_str,
            )
            return True
        return False
