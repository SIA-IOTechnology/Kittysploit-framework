#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect AD CS web enrollment endpoints (HTTP)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "AD CS Web Enrollment Detection",
        "description": "Detects Microsoft AD CS /certsrv and /CertEnroll HTTP enrollment surfaces.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["ad", "adcs", "windows", "scanner", "certificate", "enrollment"],
        "references": ["https://github.com/ly4k/Certipy"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "chain": {
                "produces_capabilities": ["adcs_surface", "enterprise_panel"],
                "suggested_followups": ["scanner/ldap/adcs_misconfig_scanner"],
            },
        },
    }

    def run(self):
        for path in (
            "/certsrv/",
            "/CertEnroll/",
            "/certsrv/mscep/mscep.dll",
            "/certsrv/certrqxt.asp",
        ):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 301, 302, 401):
                continue
            body = (r.text or "").lower()
            headers = {k.lower(): v for k, v in r.headers.items()}
            markers = (
                "certificates" in body and "microsoft" in body,
                "certsrv" in body,
                "certenroll" in body,
                "certificate services" in body,
                "mscep" in path.lower() and r.status_code in (200, 401),
                "www-authenticate" in headers and "negotiate" in headers.get("www-authenticate", "").lower(),
            )
            if not any(markers):
                continue
            if is_html_response(r) or r.status_code in (401, 302):
                self.set_info(
                    severity="medium",
                    reason="AD CS web enrollment endpoint detected",
                    path=path,
                    confidence="high",
                )
                return True
        return False
