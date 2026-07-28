#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects exposed Model Context Protocol (MCP) servers through the SSE API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MCP SSE API Exposed - Detect',
        'description': 'Detects exposed Model Context Protocol (MCP) servers through the SSE API. MCP servers often provide administrative access to AI tools, LLM systems, or other automation infrastructure. Exposed MCP interfaces can lead to unauthorized access, information disclosure, and potential system compromise. This template detects a SSE server event stream and returns the messages endpoint which can be used to POST JSON-RPC 2.0 requests.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'mcp', 'devtools', 'api', 'ai', 'llm'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': ['https://modelcontextprotocol.io/specification/2024-11-05/basic/transports#http-with-sse'],
    }

    def run(self):
        for path in ('/sse', '/mcp/sse'):
            r = self.http_request(
                method="GET",
                path=path,
                allow_redirects=False,
                headers={"Accept": "text/event-stream"},
            )
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
            # Require SSE semantics — not generic application/json in HTML/JS bodies.
            sse_header = "text/event-stream" in headers
            sse_body = (
                "event: endpoint" in body
                or "Not Acceptable: Client must accept text/event-stream" in body
            )
            if not (sse_header or sse_body):
                continue
            self.set_info(
                severity='info',
                reason="MCP SSE API Exposed detected",
                path=path,
            )
            return True
        return False

