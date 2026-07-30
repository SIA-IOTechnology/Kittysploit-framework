#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Docker Daemon exposed over HTTP API."""

import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Docker Daemon Exposed (HTTP)",
        "description": (
            "Detects an unauthenticated Docker Engine API via /version and "
            "/v{ApiVersion}/containers/json. Typical port: 2375."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "references": [
            "https://docs.docker.com/engine/security/protect-access/",
        ],
        "tags": ["web", "scanner", "docker", "misconfig", "exposure", "unauth", "vuln"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.6,
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
                    {"capability": "container_admin", "from_detail": ""},
                    {"capability": "unauth_read", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": ["scanner/tcp/docker_api_exposed"],
            },
        },
    }

    # Docker API is plain HTTP on 2375 by default
    port = OptPort(2375, "Docker API port", True)
    ssl = OptBool(False, "SSL enabled: true/false", True, advanced=True)

    def _url(self, path: str) -> str:
        host = str(getattr(getattr(self, "target", None), "value", getattr(self, "target", "")) or "").strip()
        port = getattr(getattr(self, "port", None), "value", 2375)
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            port_i = 2375
        if host.startswith(("http://", "https://")):
            return host.rstrip("/") + path
        return f"http://{host}:{port_i}{path}"

    def run(self):
        version_resp = self.http_request(method="GET", path="/version", allow_redirects=False)
        if not version_resp or version_resp.status_code != 200:
            return False
        body1 = version_resp.text or ""
        needed = ("ApiVersion", "GitCommit", "GoVersion", "KernelVersion")
        if not all(token in body1 for token in needed):
            return False

        api_version = None
        try:
            data = version_resp.json()
            api_version = str(data.get("ApiVersion") or "").strip() or None
        except Exception:
            match = re.search(r'"ApiVersion"\s*:\s*"([^"]+)"', body1)
            if match:
                api_version = match.group(1)

        if not api_version:
            return False

        containers_path = f"/v{api_version}/containers/json"
        containers_resp = self.http_request(
            method="GET", path=containers_path, allow_redirects=False
        )
        if not containers_resp or containers_resp.status_code != 200:
            return False
        body2 = containers_resp.text or ""
        ok_list = (
            ("Id" in body2 and "Names" in body2 and "Image" in body2 and "Command" in body2)
            or body2.strip() == "[]"
        )
        if not ok_list:
            # PrivatePort/PublicPort optional when empty list
            return False

        count = 0
        try:
            parsed = json.loads(body2)
            if isinstance(parsed, list):
                count = len(parsed)
        except Exception:
            count = 0

        self.report_finding(
            "Docker Daemon API exposed",
            severity="critical",
            evidence={
                "url": self._url("/version"),
                "status_code": 200,
                "api_version": api_version,
                "containers_path": containers_path,
                "container_count": count,
            },
            impact={
                "summary": "Remote attackers may list/control containers and potentially escape to the host.",
                "business_risk": "Full container infrastructure compromise",
            },
            remediation={
                "summary": "Do not expose the Docker daemon without TLS client auth.",
                "actions": [
                    "Bind Docker to localhost or a management network only",
                    "Enable TLS mutual authentication on the Docker API",
                    "Prefer a secured orchestrator API instead of raw daemon exposure",
                ],
            },
        )
        return True
