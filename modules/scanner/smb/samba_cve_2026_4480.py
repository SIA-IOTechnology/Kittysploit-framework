#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.smb.smb_client import SMBAuth, SMBClient
from lib.protocols.smb.smb_scanner_client import Smb_scanner_client


class Module(Scanner, Smb_scanner_client):
    __info__ = {
        "name": "Samba CVE-2026-4480 detection",
        "description": (
            "Fingerprints Samba and flags versions affected by CVE-2026-4480 "
            "(print-command %J command injection). Fixed upstream in 4.22.10, "
            "4.23.8, and 4.24.3. Actual exploitability also requires a custom "
            "print command that references %J and is not using cups/iprint."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-4480",
        "references": [
            "https://www.samba.org/samba/security/CVE-2026-4480.html",
            "https://www.cve.org/CVERecord?id=CVE-2026-4480",
        ],
        "modules": [
            "exploits/linux/smb/samba_cve_2026_4480_rce",
        ],
        "tags": [
            "smb",
            "scanner",
            "samba",
            "print",
            "command-injection",
            "rce",
            "cve-2026-4480",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["samba", "smb"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/linux/smb/samba_cve_2026_4480_rce",
                ],
            },
        },
    }

    smb_timeout = OptInteger(10, "SMB connection timeout in seconds", required=False, advanced=True)

    _VERSION_PATTERNS = (
        re.compile(r"Samba\s+([\d.]+)", re.I),
        re.compile(r"samba[^0-9]{0,16}([\d]+\.[\d]+\.[\d]+)", re.I),
    )

    @staticmethod
    def _version_tuple(value: str) -> Tuple[int, ...]:
        parts = []
        for token in re.findall(r"\d+", value or ""):
            parts.append(int(token))
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _parse_version(self, text: str) -> str:
        for pattern in self._VERSION_PATTERNS:
            match = pattern.search(text or "")
            if match:
                return match.group(1).strip()
        return ""

    def _is_vulnerable(self, version: str) -> Optional[bool]:
        if not version:
            return None

        current = self._version_tuple(version)
        if current >= (4, 24, 3):
            return False
        if (4, 23, 8) <= current < (4, 24, 0):
            return False
        if (4, 22, 10) <= current < (4, 23, 0):
            return False
        if current[0] in (3, 4):
            return True
        return None

    def _timeout_seconds(self) -> int:
        value = getattr(self, "smb_timeout", 10)
        if hasattr(value, "value"):
            value = value.value
        return max(int(value or 10), 3)

    def _fetch_server_os(self) -> Tuple[str, str]:
        host = self._host()
        if not host:
            return "", "target not set"

        client = SMBClient(
            host=host,
            port=self._port(),
            auth=SMBAuth(username="", password="", domain=""),
            timeout=self._timeout_seconds(),
            use_ntlm_v2=True,
            direct_tcp=True,
        )
        if not client.connect():
            client.close()
            return "", "SMB null session failed"

        try:
            os_info = ""
            if client.conn and hasattr(client.conn, "getServerOS"):
                os_info = str(client.conn.getServerOS() or "").strip()
            return os_info, "SMB negotiate"
        finally:
            client.close()

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target host is required")
            return False

        server_os, evidence = self._fetch_server_os()
        if not server_os:
            print_error(evidence or "Could not read SMB server OS banner")
            return False

        if "samba" not in server_os.lower():
            self.set_info(
                severity="info",
                reason=f"SMB server OS is not Samba ({server_os})",
            )
            return False

        version = self._parse_version(server_os)
        vuln = self._is_vulnerable(version)
        if vuln is False:
            label = version or server_os
            self.set_info(
                severity="info",
                reason=f"Samba {label} appears patched for CVE-2026-4480",
            )
            return False

        reason = f"Samba detected ({server_os}) via {evidence}"
        if version:
            reason = f"Samba {version} detected via {evidence}"
            if vuln:
                reason += "; version within CVE-2026-4480 affected range"
            else:
                reason += "; version not mapped to a fixed release (manual review advised)"

        self.set_info(
            severity="critical",
            reason=reason + "; requires print command with %J to be exploitable",
        )
        return True
