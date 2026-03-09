#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection bannières serveur / versions exposées."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Server banner detection",
        "description": "Detects revealing Server or X-Powered-By headers (version disclosure).",
        "author": "KittySploit Team",
        "severity": "info",
        "modules": [],
        "tags": ["web", "scanner", "banner", "version", "disclosure", "headers"],
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r:
            return False
        headers_lower = {k.lower(): k for k in r.headers}
        revealed = []
        if "server" in headers_lower:
            v = r.headers.get(headers_lower["server"], "")
            if v and v.strip():
                revealed.append(f"Server: {v}")
        if "x-powered-by" in headers_lower:
            v = r.headers.get(headers_lower["x-powered-by"], "")
            if v and v.strip():
                revealed.append(f"X-Powered-By: {v}")
        if "x-aspnet-version" in headers_lower:
            v = r.headers.get(headers_lower["x-aspnet-version"], "")
            if v and v.strip():
                revealed.append(f"X-AspNet-Version: {v}")
        if revealed:
            self.set_info(severity="info", reason="; ".join(revealed))
            return True
        return False
