#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vite is a frontend tooling framework for JavaScript."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Vite Dev Server - Path Traversal Detection',
        'description': 'Vite is a frontend tooling framework for JavaScript. Prior to versions 7.1.5, 7.0.7, 6.3.6, and 5.4.20, files starting with the same name with the public directory were served bypassing the `server.fs` settings. Only apps that explicitly expose the Vite dev server to the network (using --host or `server.host` config option), use the public directory feature (enabled by default), and have a symlink in the public directory are affected. Versions 7.1.5, 7.0.7, 6.3.6, and 5.4.20 fix the issue.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'vite', 'lfi', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://github.com/vitejs/vite/security/advisories/GHSA-g4jq-h2w9-997c',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-58751',
        ],
        'cve': 'CVE-2025-58751',
    }

    def run(self):
        r = self.http_request(method="GET", path='/../package.json', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('application/json',)
        body_all = (':',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="Vite Dev Server - Path Traversal detected",
                path='/../package.json',
            )
            return True
        return False

