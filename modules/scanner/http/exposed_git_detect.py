#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect publicly accessible Git metadata (/.git/HEAD, config, index, …)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PROBE_PATHS = (
    ("/.git/HEAD", "HEAD"),
    ("/.git/config", "config"),
    ("/.git/index", "index"),
)


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Exposed Git repository detection",
        "description": "Detects publicly accessible Git metadata such as /.git/HEAD or /.git/config.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "modules": [],
        "tags": ["web", "scanner", "git", "disclosure", "source-code"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "file_read", "from_detail": "lfi_path"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    def _is_git_hit(self, path: str, body: str) -> bool:
        text = (body or "").strip()
        if path.endswith("/HEAD"):
            return "ref: refs/" in text or text.startswith("ref:")
        if path.endswith("/config"):
            return "[core]" in text
        if path.endswith("/index"):
            # Git index starts with DIRC magic
            return text.startswith("DIRC") or "DIRC" in text[:8]
        return False

    def _target_url(self, path: str) -> str:
        host = str(getattr(self, "target", None) or getattr(self, "rhost", None) or "").strip()
        if hasattr(host, "value"):
            host = str(host.value or "").strip()
        port = getattr(self, "port", None) or getattr(self, "rport", None)
        port_v = getattr(port, "value", port) if port is not None else None
        ssl = getattr(self, "ssl", None)
        ssl_v = getattr(ssl, "value", ssl) if ssl is not None else None
        scheme = "https" if ssl_v in (True, "true", "True", 1, "1") else "http"
        try:
            port_i = int(port_v) if port_v not in (None, "") else (443 if scheme == "https" else 80)
        except (TypeError, ValueError):
            port_i = 443 if scheme == "https" else 80
        if host.startswith("http://") or host.startswith("https://"):
            return host.rstrip("/") + path
        return f"{scheme}://{host}:{port_i}{path}"

    def run(self):
        files_found = []
        hit_url = None
        hit_status = None

        for path, label in PROBE_PATHS:
            response = self.http_request(method="GET", path=path, allow_redirects=False)
            if not response or response.status_code != 200:
                continue
            body = response.text or ""
            if not self._is_git_hit(path, body):
                continue
            files_found.append(label)
            if hit_url is None:
                hit_url = self._target_url("/.git/")
                hit_status = int(response.status_code)

        if not files_found:
            return False

        self.report_finding(
            "Exposed Git repository",
            severity="high",
            evidence={
                "url": hit_url or self._target_url("/.git/"),
                "status_code": hit_status or 200,
                "files_found": files_found,
                # Optional: set when a screenshot artifact is produced
                # "screenshot": "evidence.png",
            },
            impact={
                "summary": "An attacker may retrieve source code and sensitive information.",
                "business_risk": "Source code disclosure",
            },
            remediation={
                "summary": "Block access to .git directories.",
                "actions": [
                    "Configure web server rules",
                    "Remove exposed repository",
                    "Rotate leaked secrets",
                ],
            },
        )
        return True
