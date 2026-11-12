#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed WordPress REST API (wp-json) and common leaky routes."""

from __future__ import annotations

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "WordPress REST API Exposure",
        "description": "Detects public /wp-json index, wp/v2 users, and route namespaces.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "wordpress", "wp", "api", "headers", "security"],
        "agent": {
            "risk": "read",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    def _get_json(self, path: str):
        response = self.http_request(method="GET", path=path, allow_redirects=True)
        if not response or int(getattr(response, "status_code", 0) or 0) >= 500:
            return None
        text = (getattr(response, "text", None) or "").strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def run(self):
        findings: list[str] = []
        index = self._get_json("/wp-json/")
        if isinstance(index, dict):
            name = str(index.get("name") or "")
            namespaces = index.get("namespaces")
            ns_count = len(namespaces) if isinstance(namespaces, list) else 0
            if name.lower() == "wordpress" or ns_count > 0:
                findings.append(f"REST index exposes {ns_count} namespace(s)")
                routes = index.get("routes") if isinstance(index.get("routes"), dict) else {}
                if "/wp/v2/users" in routes:
                    findings.append("route /wp/v2/users registered")
        else:
            resp = self.http_request(method="GET", path="/wp-json/", allow_redirects=True)
            body = (getattr(resp, "text", "") or "").lower()
            if resp and int(getattr(resp, "status_code", 0) or 0) < 500 and "wordpress" in body:
                findings.append("wp-json reachable (non-JSON or filtered)")

        users = self._get_json("/wp-json/wp/v2/users")
        if isinstance(users, list) and users:
            sample = users[0] if isinstance(users[0], dict) else {}
            uname = str(sample.get("slug") or sample.get("name") or "")
            findings.append(f"wp/v2/users lists {len(users)} user(s)" + (f" (e.g. {uname})" if uname else ""))

        types = self._get_json("/wp-json/wp/v2/types")
        if isinstance(types, dict) and types:
            keys = ", ".join(sorted(types.keys())[:8])
            findings.append(f"wp/v2/types: {keys}")

        if not findings:
            resp = self.http_request(method="GET", path="/wp-json/wp/v2", allow_redirects=True)
            if resp and int(resp.status_code or 0) in (200, 401, 403):
                findings.append(f"wp/v2 API responded HTTP {resp.status_code}")

        if not findings:
            return False

        self.set_info(
            severity="medium" if "users lists" in " ".join(findings) else "low",
            reason="WordPress REST API exposed",
            detail="; ".join(findings),
            paths=["/wp-json/", "/wp-json/wp/v2/users"],
        )
        return True
