#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQL injection scanner powered by lib.protocols.http.sqli_engine.

Minimal-request, baseline-first detection on crawl/recon surface — no payload spray.
"""

from __future__ import annotations

import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse

from kittysploit import *
from core.scanner.http.discovery import (
    build_injection_targets,
    merge_scan_paths,
    parse_csv_option,
)
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.sqli_engine import HttpParameterOracle, SqliEngine, technique_label
from lib.protocols.http.sqli_engine.oracles import ORDER_BY_PARAM_HINTS, probe_order_by_sqli
from lib.scanner.http.module_result import finalize_http_scanner_run


class Module(Auxiliary, Http_client):

    __info__ = {
        "name": "SQLi Engine Scanner",
        "description": (
            "Low-noise SQL injection detection using the KittySploit sqli_engine "
            "(error/boolean/time/union, budget-aware, crawl-driven surface only)."
        ),
        "author": "KittySploit Team",
        "tags": ["web", "sqli", "sql", "injection", "scanner", "engine"],
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://portswigger.net/web-security/sql-injection",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 12,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints", "params"],
            "chain": {
                "produces_capabilities": [
                    "db_access",
                    {"capability": "inj_param", "from_detail": "inj_param"},
                    {"capability": "inj_path", "from_detail": "inj_path"},
                    {"capability": "inj_method", "from_detail": "inj_method"},
                ],
                "suggested_followups": ["post/http/sqli_shell"],
            },
        },
    }

    scan_paths = OptString(
        "",
        "Comma-separated paths/URLs to test (typically from crawler output)",
        required=False,
        advanced=True,
    )
    extra_paths = OptString(
        "",
        "Additional paths to include (e.g. login pages from recon)",
        required=False,
        advanced=True,
    )
    seed_params = OptString(
        "",
        "Comma-separated parameter names to prioritize (from crawler/recon)",
        required=False,
        advanced=True,
    )
    blind_fallback = OptBool(
        False,
        "When no crawl/recon surface exists, probe generic params on / (noisier)",
        required=False,
        advanced=True,
    )
    allow_time = OptBool(True, "Enable time-based blind probes (skipped if WAF detected)", required=False)
    time_delay = OptPort(3, "Seconds for SLEEP/pg_sleep probes", required=False, advanced=True)
    max_requests = OptPort(16, "Max HTTP requests per parameter", required=False, advanced=True)
    waf_detected = OptBool(False, "Skip time-based probes (set when WAF is known)", required=False, advanced=True)
    test_post = OptBool(True, "Also run GET probes as POST on discovered targets", required=False, advanced=True)

    COMMON_PARAMS = [
        "id", "user", "user_id", "username", "email",
        "q", "query", "search", "filter", "sort", "order",
        "page", "limit", "offset", "category", "category_id",
    ]

    def check(self) -> bool:
        try:
            response = self.http_request(method="GET", path="/")
            return bool(response and response.status_code in (200, 301, 302, 403, 404, 401))
        except Exception:
            return False

    def _format_request_url(self, path: str, *, method: str = "GET", param: str = "", payload: str = "") -> str:
        try:
            def _gv(opt):
                return opt.value if hasattr(opt, "value") else opt

            target = _gv(self.target)
            port = int(_gv(self.port))
            protocol = "https" if (_gv(self.ssl) if hasattr(self, "ssl") else port == 443) else "http"
            p = path if str(path).startswith("/") else f"/{path}"
            base = f"{protocol}://{target}:{port}{p}"
            if method == "POST" and param:
                pl = (payload or "")[:80].replace("\n", "\\n")
                return f"{base} [POST {param}={pl!r}]"
            return base
        except Exception:
            return str(path or "/")

    def _build_get_path(self, base_path: str, param_name: str, payload: str) -> str:
        base_path = base_path if str(base_path).startswith("/") else f"/{base_path}"
        parsed = urlparse(base_path)
        path_only = parsed.path or "/"
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        params[param_name] = payload
        query = urllib.parse.urlencode(params)
        return f"{path_only}?{query}" if query else path_only

    def _original_param_value(self, base_path: str, param_name: str) -> str:
        parsed = urlparse(base_path if str(base_path).startswith("/") else f"/{base_path}")
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if key.lower() == param_name.lower():
                return value if value else "1"
        return "1"

    def _make_send_fn(
        self,
        base_path: str,
        param_name: str,
        method: str,
    ) -> Callable[..., Tuple[Any, float]]:
        method = method.upper()

        def send_payload(payload: str, timeout: Optional[float] = None) -> Tuple[Any, float]:
            start = time.time()
            kw: Dict[str, Any] = {"allow_redirects": False}
            if timeout is not None:
                kw["timeout"] = timeout

            if method == "GET":
                test_path = self._build_get_path(base_path, param_name, payload)
                response = self.http_request(method="GET", path=test_path, **kw)
            else:
                post_path = urlparse(
                    base_path if str(base_path).startswith("/") else f"/{base_path}"
                ).path or "/"
                response = self.http_request(
                    method="POST",
                    path=post_path,
                    data={param_name: payload},
                    **kw,
                )
            return response, time.time() - start

        return send_payload

    def _discovered_targets(self) -> Tuple[List[str], List[str], List[Tuple[str, str]]]:
        paths = merge_scan_paths(
            parse_csv_option(self.scan_paths),
            parse_csv_option(self.extra_paths),
        )
        seed_params = parse_csv_option(self.seed_params)
        targets = build_injection_targets(paths, seed_params)
        return paths, seed_params, targets

    def _scan_target(self, base_path: str, param: str, method: str, engine: SqliEngine) -> Dict[str, Any]:
        original = self._original_param_value(base_path, param)
        oracle = HttpParameterOracle(
            original_value=original,
            send_payload=self._make_send_fn(base_path, param, method),
        )
        scan = engine.scan_parameter(oracle, param=param, method=method, path=base_path)
        if not scan.vulnerable and param.lower() in ORDER_BY_PARAM_HINTS:
            send_fn = self._make_send_fn(base_path, param, method)
            ob_hit = probe_order_by_sqli(send_fn, original)
            if ob_hit:
                scan.vulnerable = True
                scan.technique = ob_hit.technique
                scan.injection_type = f"{technique_label(ob_hit.technique)} (ORDER BY)"
                scan.payload = ob_hit.payload
                scan.confidence = ob_hit.confidence
                scan.evidence = ob_hit.evidence
                scan.dbms = ob_hit.dbms
                scan.indicators = list(ob_hit.indicators)
                scan.status_code = ob_hit.status_code
                scan.response_time = ob_hit.response_time
                scan.response_length = ob_hit.response_length
                scan.all_hits = [ob_hit]
        hit = scan.to_hit_dict(
            request_url=self._format_request_url(
                base_path if method == "GET" else urlparse(base_path).path or "/",
                method=method,
                param=param,
                payload=scan.payload,
            )
        )
        hit["request_count"] = scan.request_count
        return hit

    def run(self):
        self.vulnerabilities = []
        self.test_results = []

        if not self.check():
            print_error("Target is not reachable, aborting SQLi engine scan.")
            self.vulnerability_info = {"reason": "Target is not reachable", "severity": "Info"}
            return False

        print_status("Starting SQLi engine scan (minimal probes)...")
        print_info(f"Target: {self.target}")
        print_info("")

        discovered_paths, _seed_params, discovered_targets = self._discovered_targets()
        use_blind = bool(self._to_bool(getattr(self, "blind_fallback", False)))
        allow_time = bool(self._to_bool(getattr(self, "allow_time", True)))
        waf = bool(self._to_bool(getattr(self, "waf_detected", False)))
        test_post = bool(self._to_bool(getattr(self, "test_post", True)))

        try:
            time_delay = float(self.time_delay.value if hasattr(self.time_delay, "value") else self.time_delay)
        except (TypeError, ValueError):
            time_delay = 3.0
        try:
            max_requests = int(self.max_requests.value if hasattr(self.max_requests, "value") else self.max_requests)
        except (TypeError, ValueError):
            max_requests = 16

        engine = SqliEngine(
            allow_time=allow_time,
            time_delay=time_delay,
            waf_detected=waf,
            max_requests=max_requests,
            stop_on_first=True,
        )

        total_requests = 0
        print_keys: set = set()
        live_cap = 48
        live_printed = 0

        def _record_hit(hit: Dict[str, Any]) -> None:
            nonlocal live_printed, total_requests
            self.test_results.append(hit)
            total_requests += int(hit.get("request_count") or 0)
            if not hit.get("vulnerable"):
                return
            self.vulnerabilities.append(hit)
            key = (hit.get("method"), hit.get("param"), hit.get("request_url"))
            if key in print_keys or live_printed >= live_cap:
                return
            print_keys.add(key)
            live_printed += 1
            pl = hit.get("payload") or ""
            pl_show = pl if len(pl) <= 100 else (pl[:97] + "…")
            rt = hit.get("response_time")
            rt_s = f" | t={rt:.2f}s" if isinstance(rt, (int, float)) else ""
            conf = hit.get("confidence")
            conf_s = f" | conf={conf}" if conf else ""
            dbms = hit.get("dbms")
            dbms_s = f" | dbms={dbms}" if dbms else ""
            print_success(
                f"[!] SQLi | {hit.get('method')} {hit.get('request_url', '')} "
                f"| param={hit.get('param')} | {hit.get('injection_type', 'Unknown')} "
                f"| status={hit.get('status_code')} | req={hit.get('request_count')}"
                f"{conf_s}{dbms_s}{rt_s} | payload={pl_show!r}"
            )
            inds = ", ".join(hit.get("indicators") or [])[:400]
            if inds:
                print_success(f"    indicators: {inds}")
            ev = (hit.get("evidence_snippet") or "").strip()
            if ev:
                print_success(f"    evidence: {ev[:700]}{'…' if len(ev) > 700 else ''}")

        if discovered_targets:
            print_status(
                f"Scanning discovered surface ({len(discovered_targets)} path/param pair(s) "
                f"from {len(discovered_paths)} path(s))..."
            )
            print_info("")
            for base_path, param in discovered_targets:
                print_info(f"GET probe: {base_path} [param={param}]")
                hit = self._scan_target(base_path, param, "GET", engine)
                _record_hit(hit)
                if test_post:
                    print_info(f"POST probe: {base_path} [param={param}]")
                    hit = self._scan_target(base_path, param, "POST", engine)
                    _record_hit(hit)
            print_info("")
        elif not use_blind:
            print_warning("No crawl/recon surface and blind_fallback disabled — nothing to scan.")
            print_info("Tip: run auxiliary/scanner/http/crawler first or pass scan_paths/seed_params.")
            self.vulnerability_info = {"reason": "No discovered endpoints to test", "severity": "Info"}
            return self.module_result(success=True)
        else:
            print_warning("No crawl surface — limited fallback on / with common parameters.")
            print_info("Tip: run crawler first for better coverage with fewer requests.")
            print_info("")
            for param in self.COMMON_PARAMS[:8]:
                print_info(f"Fallback GET: / [param={param}]")
                hit = self._scan_target("/", param, "GET", engine)
                _record_hit(hit)

        print_status("=" * 60)
        print_status("SQLi Engine Scan Summary")
        print_status("=" * 60)
        print_info(f"Parameters tested: {len(self.test_results)}")
        print_info(f"Approx. HTTP requests: {total_requests}")
        print_info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        print_status("=" * 60)
        print_info("")

        if self.vulnerabilities:
            print_warning("SQL injection signals detected:")
            table_data = []
            for vuln in self.vulnerabilities[:20]:
                table_data.append([
                    vuln.get("param", ""),
                    vuln.get("method", "GET"),
                    str(vuln.get("request_url") or "")[:72],
                    vuln.get("injection_type", ""),
                    str(vuln.get("confidence") or ""),
                    (vuln.get("evidence_snippet") or "")[:48],
                ])
            if table_data:
                print_table(
                    ["Param", "Method", "URL", "Type", "Conf", "Evidence"],
                    table_data,
                )
            print_info("")

            first = self.vulnerabilities[0]
            chain_extra = {
                "sqli_findings": self.vulnerabilities[:12],
            }
            chain_extra.update({
                k: v
                for k, v in (
                    ("inj_param", str(first.get("param") or "")),
                    ("inj_method", str(first.get("method") or "GET").upper()),
                    ("technique", str(first.get("injection_type") or "")),
                    ("dbms", str(first.get("dbms") or "")),
                )
                if v
            })
            raw_url = str(first.get("request_url") or "").strip()
            if raw_url:
                parsed = urlparse(raw_url)
                inj_path = parsed.path or "/"
                if parsed.query:
                    inj_path = f"{inj_path}?{parsed.query}"
                chain_extra["inj_path"] = inj_path[:512]

            print_info(
                "Next: use post/http/sqli_shell with inj_param, inj_path, union_template "
                "for read-only extraction."
            )
            print_info("")

            summary = (
                f"{first.get('injection_type', 'SQLi')} on param={first.get('param')} "
                f"({first.get('method')}) — {str(first.get('request_url', ''))[:180]}"
            )
            return finalize_http_scanner_run(
                self,
                self.vulnerabilities,
                title="SQL Injection",
                severity="high",
                reason=f"SQLi engine: {summary}",
                category="injection",
                findings_key="sqli_findings",
                dedupe_keys=("method", "param"),
                vulnerability_info_extra=chain_extra,
            )

        print_info("No SQL injection detected with minimal probes.")
        self.vulnerability_info = {}
        return self.module_result(success=True)
