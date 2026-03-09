#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection Docker Registry (API v2)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Docker Registry detection",
        "description": "Detects Docker Registry API v2 (image listing possible).",
        "author": "KittySploit Team",
        "severity": "low",
        "modules": [],
        "tags": ["web", "scanner", "docker", "registry", "container"],
    }

    def run(self):
        r = self.http_request(method="GET", path="/v2/", allow_redirects=False)
        if not r:
            return False
        h = {k.lower(): v for k, v in r.headers.items()}
        if r.status_code == 200 and h.get("docker-distribution-api-version"):
            self.set_info(severity="low", reason="Docker Registry v2 API")
            return True
        if r.status_code == 200 and ("v2" in r.text or "docker" in r.text.lower()):
            self.set_info(severity="low", reason="Docker Registry v2 API")
            return True
        return False
