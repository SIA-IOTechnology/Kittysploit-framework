#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Apache Solr admin interfaces."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Apache Solr Detection",
        "description": "Detects Solr admin and system info endpoints.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "solr", "apache", "search"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    def run(self):
        for path in ("/solr/", "/solr/admin/info/system", "/solr/admin/cores"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 401, 403):
                continue
            body = (r.text or "").lower()
            if "solr" in body or "lucene" in body or "solr-spec-version" in body:
                self.set_info(severity="medium", reason="Apache Solr detected", path=path)
                return True
        return False
