#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bruteforce common web paths and detect interesting HTTP responses."""

from __future__ import annotations

import json
import urllib.parse
from typing import Dict, List

from kittysploit import *
from lib.protocols.http.http_client import Http_client


DEFAULT_PATHS = [
    "admin", "administrator", "login", "signin", "api", "api/v1", "api/v2",
    "backup", "backups", "config", "conf", ".env", ".git", ".git/HEAD",
    "swagger", "swagger-ui", "api-docs", "openapi.json", "graphql",
    "server-status", "status", "health", "debug", "trace", "actuator",
    "actuator/health", "phpinfo.php", "info.php", "test", "staging",
    "uploads", "files", "private", "secret", "console", "manager", "wp-admin",
    "dvwa", "dvwa/login.php", "phpMyAdmin", "phpmyadmin", "mutillidae",
]


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "HTTP Directory Bruteforce",
        "description": "Bruteforce common web paths using a built-in or custom wordlist.",
        "author": ["KittySploit Team"],
        "tags": ["web", "scanner", "bruteforce", "directory", "discovery"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 20,
        'reversible': True,
        'approval_required': False,
        'produces': ['endpoints', 'risk_signals'],
        'cost': 2.0,
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

    wordlist = OptFile("", "Optional path wordlist (file://)", required=False)
    extra_paths = OptString("", "Comma-separated extra paths", required=False)
    max_paths = OptInteger(80, "Maximum paths to request", required=False)
    interesting_status = OptString("200,201,204,301,302,307,308,401,403", "Statuses to report", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _paths(self) -> List[str]:
        paths: List[str] = []
        if self.wordlist:
            paths.extend([str(p).strip().lstrip("/") for p in self.wordlist if str(p).strip()])
        else:
            paths.extend(DEFAULT_PATHS)
        extra = str(self.extra_paths or "").strip()
        if extra:
            paths.extend([item.strip().lstrip("/") for item in extra.split(",") if item.strip()])
        deduped = []
        seen = set()
        for path in paths:
            if path and path not in seen:
                seen.add(path)
                deduped.append(path)
        return deduped[: int(self.max_paths or 80)]

    def _interesting(self, status_code: int) -> bool:
        raw = str(self.interesting_status or "200,201,204,301,302,307,308,401,403")
        try:
            values = {int(item.strip()) for item in raw.split(",") if item.strip()}
        except ValueError:
            values = {200, 301, 302, 401, 403}
        return status_code in values

    def _filter_catch_all_redirects(self, findings: List[Dict[str, object]]) -> List[Dict[str, object]]:
        """Drop paths that only share an identical redirect hop (SPA / CDN catch-all)."""
        redirect_groups: Dict[tuple, List[Dict[str, object]]] = {}
        kept: List[Dict[str, object]] = []
        for entry in findings:
            status = int(entry.get("status_code") or 0)
            if status not in (301, 302, 307, 308):
                kept.append(entry)
                continue
            sig = (
                status,
                int(entry.get("length") or 0),
                str(entry.get("location") or "").strip(),
            )
            redirect_groups.setdefault(sig, []).append(entry)

        suppressed = 0
        for sig, group in redirect_groups.items():
            if len(group) >= 3:
                suppressed += len(group)
                continue
            kept.extend(group)

        if suppressed:
            print_info(
                f"Suppressed {suppressed} path(s) with identical redirect signature "
                f"(likely catch-all / CDN redirect)"
            )
        return kept

    def check(self):
        try:
            return bool(self.http_request(method="GET", path="/"))
        except Exception:
            return False

    def run(self):
        findings: List[Dict[str, object]] = []
        for rel_path in self._paths():
            path = "/" + rel_path
            resp = self.http_request(method="GET", path=path, allow_redirects=False)
            if not resp:
                continue
            if not self._interesting(resp.status_code):
                continue
            status_code = int(resp.status_code)
            location = str(resp.headers.get("Location", "") or "").strip()
            if status_code in (301, 302, 307, 308) and location:
                parsed = urllib.parse.urlparse(location)
                location = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/') or '/'}"
            findings.append({
                "path": path,
                "status_code": status_code,
                "length": len(resp.text or ""),
                "location": location,
            })

        findings = self._filter_catch_all_redirects(findings)

        for entry in findings:
            print_info(
                f"[{entry['status_code']}] {entry['path']} ({entry['length']} bytes)"
            )

        data = {"count": len(findings), "findings": findings}
        if not findings:
            print_info("No interesting paths discovered")
        else:
            print_success(f"Interesting paths: {len(findings)}")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return data
