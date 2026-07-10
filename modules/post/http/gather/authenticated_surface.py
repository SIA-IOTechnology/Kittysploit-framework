#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Authenticated HTTP surface mapper.

After login, crawls the landing page and shallow linked paths to discover
admin panels, upload endpoints, API routes, and privileged forms.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Post, Http_client):

    __info__ = {
        "name": "Authenticated HTTP Surface Mapper",
        "description": (
            "Maps post-authentication attack surface from a landing page using "
            "session cookies — admin paths, uploads, APIs, and privileged forms."
        ),
        "author": "KittySploit Team",
        "tags": ["web", "post", "auth", "recon", "admin", "api"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 12,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "params", "risk_signals", "tech_hints"],
            "chain": {
                "consumes_capabilities": ["authenticated_session", "session_cookie"],
                "produces_capabilities": ["admin_access"],
                "option_bindings": {
                    "landing_path": "landing_path",
                    "cookies": "cookie_header",
                },
                "suggested_followups": [
                    "auxiliary/scanner/http/wp_plugin_scanner",
                    "auxiliary/scanner/http/sqli_engine",
                    "post/php/database/wordpress_user_takeover",
                ],
            },
        },
    }

    landing_path = OptString("/", "Authenticated landing path to crawl", False)
    cookies = OptString("", "Cookie header (name=value; name2=value2)", False)
    max_links = OptInteger(24, "Maximum same-origin links to probe", False)
    follow_depth = OptInteger(1, "Link depth from landing (0=landing only)", False)

    _HREF_RE = re.compile(r"""href\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
    _ACTION_RE = re.compile(r"""action\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
    _INTERESTING = (
        "admin", "upload", "api", "graphql", "config", "settings", "user",
        "account", "dashboard", "manage", "backup", "export", "import", "plugin",
        "wp-admin", "console", "panel",
    )

    def _opt(self, name: str, default: Any = "") -> Any:
        value = getattr(self, name, default)
        if hasattr(value, "value"):
            return value.value
        return value

    def _apply_cookies(self) -> None:
        raw = str(self._opt("cookies") or "").strip()
        if not raw:
            return
        for part in raw.split(";"):
            piece = part.strip()
            if not piece or "=" not in piece:
                continue
            name, value = piece.split("=", 1)
            self.set_cookie(name.strip(), value.strip())

    def _normalize_link(self, href: str, base: str) -> str:
        href = (href or "").strip()
        if not href or href.startswith("#") or href.lower().startswith("javascript:"):
            return ""
        joined = urljoin(base, href)
        parsed = urlparse(joined)
        if parsed.scheme not in ("http", "https"):
            return ""
        return parsed.path or "/"

    def _extract_links(self, body: str, base_path: str) -> List[str]:
        links: List[str] = []
        for regex in (self._HREF_RE, self._ACTION_RE):
            for match in regex.findall(body or ""):
                path = self._normalize_link(match, base_path)
                if path and path not in links:
                    links.append(path)
        return links

    def _classify_path(self, path: str) -> List[str]:
        low = path.lower()
        return [token for token in self._INTERESTING if token in low]

    def run(self):
        landing = str(self._opt("landing_path") or "/").strip() or "/"
        if not landing.startswith("/"):
            landing = f"/{landing}"

        self._apply_cookies()
        print_status(f"Mapping authenticated surface from {landing}...")

        visited: Set[str] = set()
        queue: List[str] = [landing]
        endpoints: List[Dict[str, Any]] = []
        max_links = max(1, int(self._opt("max_links") or 24))
        depth_limit = max(0, int(self._opt("follow_depth") or 1))

        while queue and len(visited) < max_links:
            path = queue.pop(0)
            if path in visited:
                continue
            visited.add(path)

            response = self.http_request(method="GET", path=path, allow_redirects=True)
            status = int(response.status_code) if response else 0
            body = (response.text or "") if response else ""
            tags = self._classify_path(path)
            has_form = "<form" in body.lower()
            has_upload = 'type="file"' in body.lower() or "multipart/form-data" in body.lower()

            row = {
                "path": path,
                "status": status,
                "tags": tags,
                "has_form": has_form,
                "has_upload": has_upload,
                "length": len(body),
            }
            endpoints.append(row)

            if tags:
                print_success(f"[{status}] {path} — interesting: {', '.join(tags)}")
            else:
                print_info(f"[{status}] {path}")

            if depth_limit > 0 and len(visited) < max_links:
                for link in self._extract_links(body, path)[:12]:
                    if link not in visited and link not in queue:
                        queue.append(link)

        interesting = [row for row in endpoints if row.get("tags") or row.get("has_upload")]
        print_status(f"Visited {len(visited)} path(s); {len(interesting)} interesting")

        details = {
            "landing_path": landing,
            "visited_count": len(visited),
            "interesting_count": len(interesting),
            "endpoints": endpoints[:40],
            "interesting_paths": [row.get("path") for row in interesting[:20]],
            "authenticated_as": "session",
        }
        if interesting:
            details["admin_access"] = "probable"

        print_success(
            f"Surface map complete — {len(interesting)} interesting path(s) "
            f"from {len(visited)} visited"
        )
        return True
