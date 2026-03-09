#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection API Kubernetes exposée."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Kubernetes API detection",
        "description": "Detects exposed Kubernetes API (version, namespaces, healthz).",
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": ["cloud", "scanner", "kubernetes", "k8s", "api", "cluster"],
    }

    def run(self):
        for path in ["/version", "/api/v1", "/api/v1/namespaces", "/healthz", "/readyz"]:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 401, 403):
                continue
            t = r.text
            # /version returns gitVersion, major, minor
            if "gitVersion" in t and ("major" in t or "minor" in t):
                self.set_info(severity="high", reason=f"Kubernetes API at {path}")
                return True
            if path.startswith("/api/v1") and ("items" in t or "kind" in t and "List" in t):
                self.set_info(severity="high", reason=f"Kubernetes API at {path}")
                return True
            if path in ("/healthz", "/readyz") and r.status_code == 200 and r.text.strip() in ("ok", "success"):
                self.set_info(severity="high", reason=f"Kubernetes health at {path}")
                return True
        return False
