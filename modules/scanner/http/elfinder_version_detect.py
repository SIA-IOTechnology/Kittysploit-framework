#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""elFinder 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'elFinder 2.1.58 - Remote Code Execution Detection',
        'description': 'elFinder 2.1.58 is vulnerable to remote code execution. This can allow an attacker to execute arbitrary code and commands on the server hosting the elFinder PHP connector, even with minimal configuration.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'technology', 'tech', 'elfinder', 'oss'],
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
        'references': ['https://github.com/Studio-42/elFinder/'],
    }

    def run(self):
        for path in ('/js/elfinder.min.js', '/js/elFinder.version.js'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_markers = ('elFinder - file manager for web', 'elFinder.prototype.version =',)
            if any(m in body for m in body_markers):
                self.set_info(
                    severity='critical',
                    reason="elFinder 2.1.58 - Remote Code Execution detected",
                    path=path,
                )
                return True
        return False

