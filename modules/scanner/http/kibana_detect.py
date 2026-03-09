#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection Kibana."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Kibana detection",
        "description": "Detects if Kibana is installed on the target.",
        "author": "KittySploit Team",
        "severity": "info",
        "modules": [],
        "tags": ["web", "scanner", "kibana", "elastic", "monitoring"],
    }

    def run(self):
        for path in ["/", "/app/kibana", "/api/status"]:
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            t = r.text.lower()
            if "kibana" in t or (path == "/api/status" and r.status_code == 200 and ("version" in t or "status" in t)):
                return True
        return False
