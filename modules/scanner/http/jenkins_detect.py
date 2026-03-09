#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection Jenkins CI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Jenkins detection",
        "description": "Detects if Jenkins CI is installed on the target.",
        "author": "KittySploit Team",
        "severity": "info",
        "modules": [],
        "tags": ["web", "scanner", "jenkins", "ci", "devops"],
    }

    def run(self):
        for path in ["/", "/jenkins", "/manage"]:
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            t = r.text.lower()
            if "jenkins" in t or "dashboard" in t and "jenkins" in r.url.lower():
                return True
        return False
