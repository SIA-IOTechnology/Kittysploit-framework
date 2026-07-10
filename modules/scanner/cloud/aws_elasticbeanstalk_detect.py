#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect AWS Elastic Beanstalk environments."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "AWS Elastic Beanstalk Detection",
        "description": "Detects Elastic Beanstalk environment hostnames and headers.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["cloud", "scanner", "aws", "elasticbeanstalk", "paas"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    def run(self):
        host = str(self.target or "").lower()
        if not (host.endswith(".elasticbeanstalk.com") or "elasticbeanstalk" in host):
            r = self.http_request(method="GET", path="/", allow_redirects=False)
            if not r:
                return False
            server = str(r.headers.get("Server", "")).lower()
            if "elasticbeanstalk" not in server and "awselb" not in server:
                return False
        self.set_info(severity="info", reason="AWS Elastic Beanstalk environment detected", host=host)
        return True
