#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Cisco CUCM CVE-2026-20230 detection",
        "description": (
            "Detects Cisco Unified Communications Manager instances exposing the "
            "webdialer WSDL endpoint used in CVE-2026-20230 (SSRF to arbitrary file "
            "write and JSP command execution)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-20230",
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-20230",
        ],
        "modules": [
            "exploits/linux/http/cisco_cucm_cve_2026_20230_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "cisco",
            "cucm",
            "ucm",
            "ssrf",
            "rce",
            "cve-2026-20230",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 'medium',
        'noise': 'low',
        'value': 'medium',
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(443, "Target HTTPS port", required=True)
    ssl = OptBool(True, "Use HTTPS", required=True)

    def run(self):
        try:
            response = self.http_request(
                method="GET",
                path="/webdialer/Version.jws",
                params={"wsdl": ""},
                allow_redirects=False,
                timeout=10,
            )
            if not response or response.status_code != 200:
                return False

            body = response.text or ""
            low = body.lower()
            if "webdialer" not in low and "wsdl" not in low:
                return False

            hostname = ""
            match = re.search(r'location="https?://([^"/]+)', body)
            if match:
                hostname = match.group(1)

            reason = "CUCM webdialer WSDL endpoint accessible"
            if hostname:
                reason += f" (hostname hint: {hostname})"

            self.set_info(
                severity="critical",
                cve="CVE-2026-20230",
                reason=reason,
                hostname=hostname or None,
            )
            return True
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
