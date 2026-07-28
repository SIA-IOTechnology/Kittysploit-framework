#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed VS Code MCP (Model Context Protocol) configuration files (mcp."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Visual Studio Code MCP Configuration ("mcp.json") Exposure Detection',
        'description': 'Detected exposed VS Code MCP (Model Context Protocol) configuration files (mcp.json) which may contain sensitive information including API keys, server endpoints, authentication tokens, and tool configurations for AI assistants and language models.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'vscode', 'config', 'mcp', 'ai'],
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
        'references': [
            'https://code.visualstudio.com/docs/copilot/chat/mcp-servers',
            'https://modelcontextprotocol.io/',
        ],
    }

    def run(self):
        for path in ('/mcp.json', '/.mcp.json'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('"mcpServers": {', '"args":',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason='Visual Studio Code MCP Configuration ("mcp.json") Exposure' + " detected",
                    path=path,
                )
                return True
        return False

