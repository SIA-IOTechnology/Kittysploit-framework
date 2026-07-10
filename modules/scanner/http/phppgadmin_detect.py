#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed phpPgAdmin panels."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "phpPgAdmin Detection",
        "description": "Detects phpPgAdmin PostgreSQL administration panels.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "phppgadmin", "postgresql", "panel"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    def run(self):
        for path in ("/phpPgAdmin/", "/phppgadmin/", "/pgsql/phppgadmin/", "/phpPgAdmin/intro.php"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            body = (r.text or "").lower()
            if "phppgadmin" in body or "postgresql" in body and "login" in body and "php" in body:
                self.set_info(severity="info", reason="phpPgAdmin panel detected", path=path)
                return True
        return False
