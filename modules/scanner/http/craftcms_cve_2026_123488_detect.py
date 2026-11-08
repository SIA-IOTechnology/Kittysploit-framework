#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Craft CMS CVE-2026-123488 unauthenticated element search SQLi."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.craftcms_element_search import probe_craft_element_search_sqli


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Craft CMS CVE-2026-123488 SQLi Detect",
        "description": (
            "CVE-2026-123488: unauthenticated SQL injection via search[attribute] on Craft CMS "
            "4.0.0–4.18.8 / 5.0.0–5.11.1. Time-based sleep() oracle (no stacked UPDATE)."
        ),
        "author": ["fixedbyreboot", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-123488"],
        "tags": ["craftcms", "sqli", "unauthenticated", "cve-2026-123488", "scanner"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-123488",
            "https://github.com/craftcms/cms/security/advisories/GHSA-qcvp-ggx3-97r6",
            "https://github.com/fixedbyreboot/CVE-2026-123488-POC",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "approval_required": True,
            "produces": ["risk_signals", "tech_hints"],
            "requires": {"tech_hints_any": ["craftcms", "craft"]},
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/craftcms_cve_2026_123488_sqli",
                    "scanner/http/craft_cms_detect",
                ],
            },
        },
    }

    search_path = OptString(
        "/index.php",
        "Search endpoint path (add ?p=search query in params if needed)",
        required=False,
    )
    search_params = OptString(
        "p=search",
        "Extra query string merged into the search request",
        required=False,
        advanced=True,
    )
    time_delay = OptInteger(5, "sleep() seconds for time-based oracle", required=False, advanced=True)

    def _search_path(self) -> str:
        path = str(self.search_path or "/index.php").strip()
        if not path.startswith("/"):
            path = "/" + path
        extra = str(self.search_params or "").strip().lstrip("?")
        if extra and "?" not in path:
            return f"{path}?{extra}"
        if extra and "?" in path:
            return f"{path}&{extra}"
        return path

    def run(self):
        delay = int(self.time_delay or 5)

        def _get(path, params=None, timeout=None):
            return self.http_request(
                method="GET",
                path=path,
                params=params,
                timeout=timeout or (delay + 20),
                allow_redirects=True,
            )

        info = probe_craft_element_search_sqli(_get, self._search_path(), delay=delay)
        if info.get("error"):
            print_status(info["error"])
            return False
        if not info.get("vulnerable"):
            print_status(f"No delay (elapsed={info.get('elapsed', 0):.2f}s)")
            return False
        detail = f"Time-based SQLi ({info.get('elapsed', 0):.1f}s >= sleep {delay}s)"
        self.report_finding(
            "Craft CMS element search SQLi (CVE-2026-123488)",
            severity="critical",
            evidence={"path": self._search_path(), "elapsed": info.get("elapsed"), "cve": "CVE-2026-123488"},
            impact={"summary": "Unauthenticated read/write of the Craft database (admin flag, credentials)."},
            remediation={"summary": "Upgrade Craft CMS to 4.18.9+ or 5.11.2+."},
        )
        self.set_info(severity="critical", cve="CVE-2026-123488", reason=detail, confidence="high")
        return True
