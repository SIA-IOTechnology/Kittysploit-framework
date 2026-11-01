#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQLi engine micro-benchmark (synthetic labs + optional live target).

Usage:
  PYTHONPATH=. python -m lib.protocols.http.sqli_engine.bench
  PYTHONPATH=. python -m lib.protocols.http.sqli_engine.bench --live http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=Submit
"""

from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .engine import SqliEngine
from .oracle import HttpParameterOracle, ProbeResponse


@dataclass
class _FakeResponse:
    status_code: int = 200
    text: str = ""


class SyntheticLab:
    """Minimal in-process app simulating common SQLi shapes."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self._body_true = "user listing " + ("x" * 400)
        self._body_false = "user listing " + ("y" * 120)

    def handle(self, value: str) -> Tuple[_FakeResponse, float]:
        started = time.perf_counter()
        v = str(value)
        if self.mode == "error_mysql":
            if v.endswith("'") or v.endswith("\"") or "CONVERT" in v.upper():
                resp = _FakeResponse(
                    200,
                    "Warning: mysql_fetch_array(): You have an error in your SQL syntax near "
                    f"'{v}' at line 1",
                )
                return resp, time.perf_counter() - started
            return _FakeResponse(200, self._body_true), time.perf_counter() - started

        if self.mode == "boolean_string":
            if "1=2" in v.replace(" ", "") or "1'='2" in v.replace(" ", ""):
                return _FakeResponse(200, self._body_false), time.perf_counter() - started
            if "1=1" in v.replace(" ", "") or "1'='1" in v.replace(" ", ""):
                return _FakeResponse(200, self._body_true), time.perf_counter() - started
            if v.endswith("'") and "AND" not in v.upper():
                return _FakeResponse(200, "syntax error near " + v), time.perf_counter() - started
            return _FakeResponse(200, self._body_true), time.perf_counter() - started

        if self.mode == "boolean_paren":
            compact = v.replace(" ", "").upper()
            paren_and = "')AND(" in compact
            if v.endswith("'") and not paren_and and "AND" not in v.upper():
                return _FakeResponse(200, "You have an error in your SQL syntax near '" + v), time.perf_counter() - started
            if paren_and and ("1=2" in compact or "1'='2" in compact):
                return _FakeResponse(200, self._body_false), time.perf_counter() - started
            if paren_and and ("1=1" in compact or "1'='1" in compact):
                return _FakeResponse(200, self._body_true), time.perf_counter() - started
            if v.endswith("')") and "AND" not in v.upper():
                return _FakeResponse(200, "unclosed paren near " + v), time.perf_counter() - started
            if "AND" in v.upper() and not paren_and:
                return _FakeResponse(200, self._body_false), time.perf_counter() - started
            return _FakeResponse(200, self._body_true), time.perf_counter() - started

        if self.mode == "union_reflect":
            if "UNION SELECT" in v.upper() and "0x4b535049" in v.upper():
                return _FakeResponse(200, "rows: KSPI|null"), time.perf_counter() - started
            if "ORDER BY" in v.upper():
                try:
                    col = int(v.upper().split("ORDER BY")[-1].split("-")[0].strip().split()[0])
                except ValueError:
                    col = 99
                if col > 3:
                    return _FakeResponse(500, "Unknown column '99' in order clause"), time.perf_counter() - started
                return _FakeResponse(200, self._body_true), time.perf_counter() - started
            if v.endswith("'"):
                return _FakeResponse(200, "sql syntax error"), time.perf_counter() - started
            return _FakeResponse(200, self._body_true), time.perf_counter() - started

        return _FakeResponse(200, ""), time.perf_counter() - started


def _oracle_for_lab(lab: SyntheticLab, original: str = "1") -> HttpParameterOracle:
    def send_payload(payload: str, timeout: Optional[float] = None) -> Tuple[_FakeResponse, float]:
        return lab.handle(payload)

    return HttpParameterOracle(original_value=original, send_payload=send_payload)


@dataclass
class BenchCase:
    case_id: str
    mode: str
    expect_technique_prefix: str = "error"
    expect_boundary_paren: bool = False


@dataclass
class BenchResult:
    case_id: str
    vulnerable: bool
    technique: str
    request_count: int
    confidence: int
    passed: bool
    injection_context: Dict[str, Any] = field(default_factory=dict)
    evidence: str = ""


def run_synthetic_case(case: BenchCase) -> BenchResult:
    lab = SyntheticLab(case.mode)
    oracle = _oracle_for_lab(lab)
    engine = SqliEngine(max_requests=40, stop_on_first=False, allow_time=False)
    scan = engine.scan_parameter(oracle, param="id", method="GET", path="/")
    technique = scan.technique or ""
    passed = scan.vulnerable and technique.startswith(case.expect_technique_prefix.split("_")[0])
    if case.expect_technique_prefix == "boolean" and technique not in ("boolean", "boolean_numeric"):
        passed = scan.vulnerable and technique in ("boolean", "boolean_numeric", "union", "error")
    if case.expect_boundary_paren:
        passed = passed and bool((scan.injection_context or {}).get("paren_close") == ")")
    if case.mode == "union_reflect":
        passed = scan.vulnerable and scan.technique in ("union", "error", "boolean")
    return BenchResult(
        case_id=case.case_id,
        vulnerable=scan.vulnerable,
        technique=technique,
        request_count=scan.request_count,
        confidence=scan.confidence,
        passed=passed,
        injection_context=dict(scan.injection_context or {}),
        evidence=scan.evidence or "",
    )


def run_synthetic_suite() -> List[BenchResult]:
    cases = [
        BenchCase("mysql_error", "error_mysql", "error"),
        BenchCase("boolean_string", "boolean_string", "boolean"),
        BenchCase("boolean_paren", "boolean_paren", "boolean", expect_boundary_paren=True),
        BenchCase("union_enum", "union_reflect", "union"),
    ]
    return [run_synthetic_case(c) for c in cases]


def run_live_target(url: str, *, param: str = "id", cookie: str = "") -> BenchResult:
    import requests

    parsed_param = param
    original = "1"

    def send_payload(payload: str, timeout: Optional[float] = None) -> Tuple[Any, float]:
        started = time.perf_counter()
        sep = "&" if "?" in url else "?"
        if "=" in url.split("?")[-1]:
            target = url.replace(f"{parsed_param}={original}", f"{parsed_param}={payload}")
            if target == url:
                target = f"{url}{sep}{parsed_param}={payload}"
        else:
            target = f"{url}{sep}{parsed_param}={payload}"
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        try:
            resp = requests.get(target, headers=headers, timeout=timeout or 15, verify=False)
        except Exception:
            return None, time.perf_counter() - started
        return resp, time.perf_counter() - started

    oracle = HttpParameterOracle(original_value=original, send_payload=send_payload)
    engine = SqliEngine(max_requests=40, stop_on_first=False, allow_time=True)
    scan = engine.scan_parameter(oracle, param=parsed_param, method="GET", path=url)
    return BenchResult(
        case_id="live",
        vulnerable=scan.vulnerable,
        technique=scan.technique or "",
        request_count=scan.request_count,
        confidence=scan.confidence,
        passed=scan.vulnerable,
        injection_context=dict(scan.injection_context or {}),
        evidence=scan.evidence or "",
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="KittySploit native SQLi engine benchmark")
    parser.add_argument("--live", metavar="URL", help="Optional live lab URL (e.g. DVWA SQLi)")
    parser.add_argument("--param", default="id", help="Query parameter name for --live")
    parser.add_argument("--cookie", default=os.environ.get("KITTY_SQli_BENCH_COOKIE", ""))
    parser.add_argument("--json", action="store_true", help="Print JSON only")
    args = parser.parse_args(argv)

    results = run_synthetic_suite()
    if args.live:
        results.append(run_live_target(args.live, param=args.param, cookie=args.cookie))

    passed = sum(1 for r in results if r.passed)
    payload = {
        "passed": passed,
        "total": len(results),
        "ok": passed == len(results),
        "results": [r.__dict__ for r in results],
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"SQLi bench: {passed}/{len(results)} passed")
        for row in results:
            status = "PASS" if row.passed else "FAIL"
            print(
                f"  [{status}] {row.case_id}: vuln={row.vulnerable} "
                f"technique={row.technique} requests={row.request_count} "
                f"context={row.injection_context}"
            )
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
