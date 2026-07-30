#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Laravel .env sensitive information disclosure."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PATHS = (
    "/.env",
    "/.env.bak",
    "/.env.dev",
    "/.env.dev.local",
    "/.env.development.local",
    "/.env.prod",
    "/.env.prod.local",
    "/.env.production",
    "/.env.production.local",
    "/.env.local",
    "/.env.example",
    "/.env.stage",
    "/.env.live",
    "/.env.backup",
    "/.env.save",
    "/.env.old",
    "/.env.www",
    "/.env_1",
    "/.env_sample",
    "/api/.env",
)

_APP_RE = re.compile(r"(?mi)^APP_(NAME|ENV|KEY|DEBUG|URL|PASSWORD)=")
_DB_RE = re.compile(r"(?mi)^DB_(HOST|PASSWORD|DATABASE)=")


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Laravel .env disclosure",
        "description": (
            "Detects publicly accessible Laravel .env files that may leak database "
            "credentials, APP_KEY, and other secrets."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "references": [
            "https://laravel.com/docs/master/configuration#environment-configuration",
        ],
        "tags": ["web", "scanner", "exposure", "laravel", "config", "env", "vuln"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 20,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.4,
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
                "produces_capabilities": [{"capability": "file_read", "from_detail": ""}],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    def _url(self, path: str) -> str:
        host = str(getattr(getattr(self, "target", None), "value", getattr(self, "target", "")) or "").strip()
        port = getattr(getattr(self, "port", None), "value", getattr(self, "port", 80))
        ssl = getattr(getattr(self, "ssl", None), "value", getattr(self, "ssl", False))
        scheme = "https" if ssl in (True, "true", "True", 1, "1") else "http"
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            port_i = 443 if scheme == "https" else 80
        if host.startswith(("http://", "https://")):
            return host.rstrip("/") + path
        return f"{scheme}://{host}:{port_i}{path}"

    def run(self):
        host = str(getattr(getattr(self, "target", None), "value", getattr(self, "target", "")) or "").strip()
        extra = []
        if host:
            # Also probe host/domain-derived .env names
            host_clean = host.split("://")[-1].split("/")[0].split(":")[0]
            parts = [p for p in host_clean.split(".") if p]
            if parts:
                extra.append(f"/.env.{parts[0]}")
            if len(parts) >= 2:
                extra.append(f"/.env.{'.'.join(parts[-2:])}")

        for path in list(PATHS) + extra:
            response = self.http_request(method="GET", path=path, allow_redirects=False)
            if not response or response.status_code != 200:
                continue
            ctype = str(response.headers.get("Content-Type") or "").lower()
            if "text/html" in ctype:
                continue
            body = response.text or ""
            if not (_APP_RE.search(body) or _DB_RE.search(body)):
                continue

            keys = []
            if _APP_RE.search(body):
                keys.append("APP_*")
            if _DB_RE.search(body):
                keys.append("DB_*")
            self.report_finding(
                "Laravel .env file exposed",
                severity="high",
                evidence={
                    "url": self._url(path),
                    "status_code": 200,
                    "path": path,
                    "keys_found": keys,
                },
                impact={
                    "summary": "Environment secrets (APP_KEY, DB credentials, tokens) may be disclosed.",
                    "business_risk": "Credential and source-config disclosure",
                },
                remediation={
                    "summary": "Block public access to .env files.",
                    "actions": [
                        "Deny .env* in the web server / reverse proxy",
                        "Move secrets to a secure vault or host env",
                        "Rotate exposed APP_KEY and database credentials",
                    ],
                },
            )
            return True
        return False
