#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Server-Side Template Injection (SSTI) on common reflection points."""

from __future__ import annotations

import json
from typing import Dict, List, Tuple
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PAYLOADS: Tuple[Tuple[str, str, str], ...] = (
    ("jinja2", "{{7*7}}", "49"),
    ("jinja2", "{{7*'7'}}", "7777777"),
    ("mako", "${7*7}", "49"),
    ("freemarker", "${7*7}", "49"),
    ("erb", "<%= 7*7 %>", "49"),
    ("twig", "{{7*7}}", "49"),
    ("smarty", "{7*7}", "49"),
)

DEFAULT_PARAMS = [
    "q",
    "query",
    "search",
    "name",
    "message",
    "template",
    "content",
    "id",
    "view",
    "page",
]


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "SSTI Probe",
        "description": "Detects Server-Side Template Injection via benign math evaluation payloads.",
        "author": ["KittySploit Team"],
        "tags": ["web", "ssti", "template", "injection", "scanner"],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 10,
        'reversible': True,
        'approval_required': False,
        'produces': ['risk_signals', 'params'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'endpoints', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    path = OptString("/", "Base path to test", required=True)
    params = OptString(
        "q,query,search,name,message,template,content,id,view,page",
        "Comma-separated parameter names to inject",
        required=False,
    )
    methods = OptChoice("GET", "HTTP method for injection", required=True, choices=["GET", "POST"])
    output_file = OptString("", "Optional JSON output file", required=False)

    def _param_list(self) -> List[str]:
        raw = str(self.params or "").strip()
        if not raw:
            return list(DEFAULT_PARAMS)
        values = [item.strip() for item in raw.split(",") if item.strip()]
        return values or list(DEFAULT_PARAMS)

    def _baseline(self, param: str) -> str:
        if str(self.methods).upper() == "POST":
            resp = self.http_request(
                method="POST",
                path=str(self.path or "/"),
                data={param: "kittysploit"},
            )
        else:
            resp = self.http_request(
                method="GET",
                path=f"{self.path}?{param}=kittysploit",
            )
        return (resp.text or "") if resp else ""

    def _inject(self, param: str, payload: str) -> str:
        if str(self.methods).upper() == "POST":
            resp = self.http_request(
                method="POST",
                path=str(self.path or "/"),
                data={param: payload},
            )
        else:
            resp = self.http_request(
                method="GET",
                path=f"{self.path}?{quote(param)}={quote(payload)}",
            )
        return (resp.text or "") if resp else ""

    def _looks_like_ssti(self, baseline: str, body: str, expected: str, payload: str) -> bool:
        if not body or expected not in body:
            return False
        if expected in baseline:
            return False
        if payload in body and expected not in body.replace(payload, ""):
            return False
        return True

    def check(self):
        try:
            resp = self.http_request(method="GET", path=str(self.path or "/"))
            return bool(resp)
        except Exception:
            return False

    def run(self):
        findings: List[Dict[str, str]] = []
        for param in self._param_list():
            baseline = self._baseline(param)
            for engine, payload, expected in PAYLOADS:
                body = self._inject(param, payload)
                if self._looks_like_ssti(baseline, body, expected, payload):
                    finding = {
                        "parameter": param,
                        "engine": engine,
                        "payload": payload,
                        "expected": expected,
                        "path": str(self.path or "/"),
                        "method": str(self.methods).upper(),
                    }
                    findings.append(finding)
                    print_warning(
                        f"SSTI signal ({engine}) on {finding['method']} {finding['path']} "
                        f"param={param} payload={payload}"
                    )
                    break

        data = {"findings": findings, "count": len(findings)}
        if not findings:
            print_info("No SSTI signals detected")
        else:
            print_success(f"SSTI findings: {len(findings)}")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return data
