#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Sonatype Nexus repository manager."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Nexus Repository Detection",
        "description": "Detects Nexus/Artifactory-style repository manager APIs.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "nexus", "sonatype", "devops", "panel"],
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
        for path in ("/service/rest/v1/status", "/repository/", "/nexus/"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            body = (r.text or "").lower()
            if "nexus" in body or "sonatype" in body or "repository manager" in body:
                self.set_info(severity="info", reason="Nexus repository manager detected", path=path)
                return True
        return False
