#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection Grafana."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Grafana detection",
        "description": "Detects if Grafana is installed on the target.",
        "author": "KittySploit Team",
        "severity": "info",
        "modules": [],
        "tags": ["web", "scanner", "grafana", "monitoring", "dashboard"],
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r:
            return False
        if "grafana" in r.text.lower() or r.url.rstrip("/").endswith("/login"):
            r2 = self.http_request(method="GET", path="/api/health", allow_redirects=False)
            if r2 and r2.status_code == 200 and "database" in r2.text.lower():
                return True
        if "grafana" in r.text.lower():
            return True
        return False
