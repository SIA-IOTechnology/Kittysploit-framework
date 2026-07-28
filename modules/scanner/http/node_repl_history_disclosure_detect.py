#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Node."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Node.js REPL History Disclosure Detection',
        'description': 'The Node.js REPL history file (.node_repl_history) was exposed, which had contained a log of commands entered into the Node.js interactive shell.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'nodejs', 'history', 'disclosure', 'misconfiguration'],
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
            'https://nodejs.org/api/repl.html#persistent-history',
            'https://joshtronic.com/2022/12/18/nodejs-repl-history/',
        ],
    }

    def run(self):
        for path in ('/.node_repl_history', '/node_repl_history'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('require(', '.exit', 'module.exports', 'let', 'process.', 'console.log(',)
            header_any = ('application/octet-stream',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='low',
                    reason="Node.js REPL History Disclosure detected",
                    path=path,
                )
                return True
        return False

