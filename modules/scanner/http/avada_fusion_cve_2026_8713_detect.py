#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Avada Fusion Builder <= 3.15.3 arbitrary file deletion (CVE-2026-8713)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "fusion-builder"
_VULN_HIGH = (3, 15, 3)
_VER_RE = re.compile(
    r"fusion-builder/assets/css/media/fullwidth[^\"']*\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    re.I,
)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Avada Fusion Builder CVE-2026-8713 detect",
        "description": (
            "Passive detect: fusion-builder asset version <= 3.15.3 (arbitrary file delete)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-8713",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-8713"],
        "modules": ["auxiliary/admin/http/avada_fusion_cve_2026_8713_file_delete"],
        "tags": ["web", "scanner", "wordpress", "avada", "file-delete", "cve-2026-8713"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/avada_fusion_cve_2026_8713_file_delete"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        html = home.text or "" if home else ""
        if "fusion-builder" not in html:
            readme = self.http_request(
                method="GET",
                path=self._join("/wp-content/plugins/fusion-builder/readme.txt"),
                allow_redirects=False,
            )
            if not readme or "Avada" not in (readme.text or ""):
                return False
            ver = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        else:
            m = _VER_RE.search(html)
            ver = m.group(1) if m else (
                self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
            )
        if ver and self.wp_version_in_range(ver, (0, 0, 0), _VULN_HIGH):
            self.set_info(
                severity="critical",
                reason=f"Fusion Builder {ver} vulnerable to fusion_form_maybe_delete_files",
                cve="CVE-2026-8713",
            )
            return True
        return False
