#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MCP server authentication abuse: unauthenticated tools/list and SSE endpoints."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.mcp_auth_probe import scan_mcp_auth_surface


class Module(Scanner, Http_client):
    __info__ = {
        "name": "MCP Server Auth Abuse Detection",
        "description": (
            "Probes Model Context Protocol SSE transports and JSON-RPC message endpoints "
            "for unauthenticated tools/list and exposed MCP admin surfaces."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "mcp", "ai", "llm", "jsonrpc", "sse", "auth"],
        "references": ["https://modelcontextprotocol.io/"],
        "modules": ["scanner/http/exposed_mcp_sse_server_detect"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.35,
            "value": 1.2,
            "chain": {
                "suggested_followups": ["scanner/http/exposed_mcp_sse_server_detect"],
            },
        },
    }

    def run(self):
        findings = scan_mcp_auth_surface(self.http_request)
        if not findings:
            return False
        critical = [f for f in findings if f.get("severity") == "critical"]
        self.set_info(
            severity="critical" if critical else "high",
            reason=f"MCP auth abuse surface ({len(findings)} hit(s))",
            path=findings[0].get("path") or "/sse",
            findings=findings[:10],
        )
        return True
