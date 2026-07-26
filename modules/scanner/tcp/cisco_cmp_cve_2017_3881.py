#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Cisco IOS telnet exposure for CVE-2017-3881 (CMP / CISCO_KITS)."""

from __future__ import annotations

import re
import socket
from typing import Dict

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client

# Common Catalyst telnet option negotiation seen in Artem Kondratenko's PoC
_CISCO_IAC_MARKERS = (
    b"\xff\xfb\x01\xff\xfb\x03",
    b"\xff\xfd\x18\xff\xfd\x1f",
)

_VERSION_RE = re.compile(
    r"(?:Cisco\s+)?IOS(?:\s+XE)?\s+Software,\s+Version\s+([\d.()A-Z-]+)",
    re.I,
)

_CISCO_TEXT_HINTS = ("cisco", "ios", "catalyst", "switch")


def _probe_cisco_telnet(host: str, port: int, timeout: float) -> Dict[str, object]:
    result: Dict[str, object] = {
        "detected": False,
        "cisco_likely": False,
        "banner": "",
        "raw_len": 0,
        "version": "",
        "error": "",
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, int(port)))
        data = sock.recv(1024)
        if not data:
            result["error"] = "empty_banner"
            return result

        result["raw_len"] = len(data)
        banner = data.decode("utf-8", errors="replace")
        result["banner"] = banner
        result["detected"] = True

        lowered = banner.lower()
        text_hit = any(h in lowered for h in _CISCO_TEXT_HINTS)
        iac_hit = any(marker in data for marker in _CISCO_IAC_MARKERS)
        result["cisco_likely"] = text_hit or iac_hit

        match = _VERSION_RE.search(banner)
        if match:
            result["version"] = match.group(1).strip()
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        try:
            sock.close()
        except Exception:
            pass


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Cisco IOS CMP CVE-2017-3881 telnet exposure",
        "description": (
            "Passive check for CVE-2017-3881 exposure: telnet reachable on a Cisco IOS "
            "or IOS XE device. CMP malformed-option handling is tied to telnet session "
            "negotiation; confirm patch level separately before exploitation."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2017-3881",
        "references": [
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170317-cmp",
            "https://artkond.com/2017/04/10/cisco-catalyst-remote-code-execution/",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-3881",
        ],
        "modules": [
            "auxiliary/admin/telnet/cisco_cmp_cve_2017_3881_credless_privesc",
        ],
        "tags": [
            "scanner",
            "tcp",
            "telnet",
            "cisco",
            "ios",
            "ios-xe",
            "catalyst",
            "cmp",
            "cve-2017-3881",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.1,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["cisco", "ios", "catalyst", "telnet"],
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
                    {"capability": "admin_access", "from_detail": "ios_cmp_telnet"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/admin/telnet/cisco_cmp_cve_2017_3881_credless_privesc",
                ],
            },
        },
    }

    port = OptPort(23, "Target Telnet port", required=True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host:
            print_error("Target host is required")
            return False
        if not self.is_tcp_open(host=host, port=port):
            return False

        info = _probe_cisco_telnet(host, port, self._timeout())
        if not info.get("detected"):
            if info.get("error"):
                print_error(str(info.get("error")))
            return False

        banner = str(info.get("banner") or "")[:200]
        version = str(info.get("version") or "").strip()
        cisco_likely = bool(info.get("cisco_likely"))

        if cisco_likely:
            reason = (
                "Cisco IOS telnet reachable — CVE-2017-3881 CMP attack surface "
                "(malformed CISCO_KITS options) if firmware is unpatched"
            )
            if version:
                reason += f"; banner IOS version hint: {version}"
            self.set_info(
                severity="critical",
                reason=reason,
                banner=banner,
                version=version or None,
            )
            return True

        self.set_info(
            severity="medium",
            reason=(
                "Telnet service detected; Cisco fingerprint not confirmed — "
                "CVE-2017-3881 may still apply on unpatched IOS devices"
            ),
            banner=banner,
        )
        return True
