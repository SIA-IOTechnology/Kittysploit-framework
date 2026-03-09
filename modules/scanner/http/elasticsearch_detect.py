#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection Elasticsearch (API REST exposée)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Elasticsearch detection",
        "description": "Detects exposed Elasticsearch REST API (often unauthenticated).",
        "author": "KittySploit Team",
        "severity": "medium",
        "modules": [],
        "tags": ["web", "scanner", "elasticsearch", "elastic", "database", "disclosure"],
    }

    def run(self):
        for path in ["/", "/_cluster/health", "/_nodes"]:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            t = r.text.lower()
            if "cluster_name" in t or "tagline" in t and "elasticsearch" in t or "version" in t and "number" in t:
                self.set_info(severity="medium", reason="Elasticsearch API exposed")
                return True
        return False
