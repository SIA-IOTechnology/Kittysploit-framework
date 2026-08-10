#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Express.js NODE_ENV=development stack-trace disclosure."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Express.js - Debug Mode Stack Trace Disclosure',
        'description': (
            'Detects Express apps running with NODE_ENV=development (or similar debug error '
            'handlers) by sending a GET with Content-Type: application/json and a non-JSON '
            'body, then looking for a 400 response that leaks a SyntaxError stack / node_modules path.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'express', 'nodejs', 'debug', 'information-disclosure',
            'misconfig', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 0.5,
            'noise': 0.2,
            'value': 0.7,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://expressjs.com/en/advanced/best-practice-performance.html#set-node_env-to-production',
        ],
    }

    path = OptString('/', 'Path to probe', required=False)

    def run(self):
        path = str(self.path or '/')
        if not path.startswith('/'):
            path = '/' + path
        body = secrets.token_hex(4)
        r = self.http_request(
            method='GET',
            path=path,
            data=body,
            headers={'Content-Type': 'application/json'},
            allow_redirects=False,
        )
        if not r or r.status_code != 400:
            return False
        text = r.text or ''
        if re.search(
            r'(>SyntaxError\s*:\s*Unexpected token|at .*/node_modules/.+\.js)',
            text,
        ):
            self.set_info(
                severity='medium',
                reason='Express debug/error handler leaked stack trace (NODE_ENV != production)',
                path=path,
            )
            return True
        return False
