#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Probe exposed OpenAPI/Swagger specs for unauthenticated sensitive endpoints."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


SPEC_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/api/openapi.json",
]

SENSITIVE_KEYWORDS = (
    "admin",
    "user",
    "account",
    "token",
    "secret",
    "password",
    "config",
    "internal",
    "debug",
    "export",
    "download",
    "upload",
    "delete",
    "role",
    "permission",
)


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "OpenAPI Schema Abuse",
        "description": (
            "Discovers exposed OpenAPI/Swagger documents and probes documented GET "
            "endpoints for unauthenticated access to sensitive routes."
        ),
        "author": ["KittySploit Team"],
        "tags": ["web", "api", "openapi", "swagger", "scanner", "misconfig"],
        "references": [
            "https://owasp.org/www-project-api-security/",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 8,
        'reversible': True,
        'approval_required': False,
        'produces': ['endpoints', 'risk_signals', 'tech_hints'],
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

    max_endpoints = OptInteger(20, "Maximum documented endpoints to probe", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _load_spec(self, body: str) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(body)
        except Exception:
            return None

    def _is_protected(self, operation: Dict[str, Any], spec: Dict[str, Any]) -> bool:
        if operation.get("security"):
            return True
        if spec.get("security"):
            return True
        return False

    def _extract_get_endpoints(self, spec: Dict[str, Any], limit: int) -> List[Dict[str, str]]:
        endpoints: List[Dict[str, str]] = []
        paths = spec.get("paths") or {}
        if not isinstance(paths, dict):
            return endpoints
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            get_op = methods.get("get")
            if not isinstance(get_op, dict):
                continue
            if self._is_protected(get_op, spec):
                continue
            summary = str(get_op.get("summary") or get_op.get("operationId") or "").lower()
            path_l = str(path).lower()
            sensitive = any(word in path_l or word in summary for word in SENSITIVE_KEYWORDS)
            endpoints.append({
                "path": str(path),
                "summary": str(get_op.get("summary") or ""),
                "sensitive": sensitive,
            })
            if len(endpoints) >= limit:
                break
        endpoints.sort(key=lambda item: (not item["sensitive"], item["path"]))
        return endpoints

    def _probe_endpoint(self, path: str) -> Tuple[Optional[int], str]:
        resp = self.http_request(method="GET", path=path, allow_redirects=False)
        if not resp:
            return None, "request_failed"
        if resp.status_code in (401, 403):
            return resp.status_code, "protected"
        if resp.status_code >= 500:
            return resp.status_code, "server_error"
        if resp.status_code in (200, 201, 202, 204):
            body = (resp.text or "").lower()
            if any(token in body for token in ("password", "secret", "token", "apikey", "api_key")):
                return resp.status_code, "sensitive_body"
            return resp.status_code, "accessible"
        return resp.status_code, "other"

    def check(self):
        try:
            resp = self.http_request(method="GET", path="/", allow_redirects=True)
            return bool(resp)
        except Exception:
            return False

    def run(self):
        spec_url = ""
        spec: Optional[Dict[str, Any]] = None
        for path in SPEC_PATHS:
            resp = self.http_request(method="GET", path=path, allow_redirects=False)
            if not resp or resp.status_code != 200:
                continue
            parsed = self._load_spec(resp.text or "")
            if parsed and isinstance(parsed.get("paths"), dict):
                spec = parsed
                spec_url = path
                break

        if not spec:
            print_info("No exposed OpenAPI/Swagger document found")
            return {"found": False}

        endpoints = self._extract_get_endpoints(spec, int(self.max_endpoints or 20))
        print_success(f"OpenAPI spec found at {spec_url} — probing {len(endpoints)} GET endpoint(s)")

        findings: List[Dict[str, Any]] = []
        for entry in endpoints:
            status, signal = self._probe_endpoint(entry["path"])
            result = {**entry, "status_code": status, "signal": signal}
            findings.append(result)
            if signal in ("accessible", "sensitive_body"):
                level = "warning" if signal == "sensitive_body" else "info"
                msg = f"[{status}] {entry['path']} — {signal}"
                print_warning(msg) if level == "warning" else print_info(msg)

        exposed = [f for f in findings if f.get("signal") in ("accessible", "sensitive_body")]
        data = {
            "found": True,
            "spec_url": spec_url,
            "title": spec.get("info", {}).get("title", ""),
            "version": spec.get("info", {}).get("version", ""),
            "probed": findings,
            "exposed_count": len(exposed),
        }
        print_success(f"Probe complete — exposed endpoints: {len(exposed)}")
        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return data
