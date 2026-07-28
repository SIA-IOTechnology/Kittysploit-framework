#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fohrloop dash-uploader v0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'dash-uploader 0.1.0 - 0.7.0a2 - Denial-of-Service via flowTotalChunks Detection',
        'description': 'fohrloop dash-uploader v0.1.0 through v0.7.0a2 contains a remote code execution caused by improper handling in Upload function and max_file_size parameter in dash_uploader components, letting remote attackers execute arbitrary code, exploit requires crafted request.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'dash-uploader', 'unauth', 'python', 'passive'],
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
            'https://github.com/a1ohadance/CVE-2026-38361',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-38361',
            'https://github.com/advisories/GHSA-xp7f-v245-w3w8',
            'https://github.com/fohrloop/dash-uploader/issues/153',
        ],
        'cve': 'CVE-2026-38361',
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('dash_uploader',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="dash-uploader 0.1.0 - 0.7.0a2 - Denial-of-Service via flowTotalChunks detected",
                path='/',
            )
            return True
        return False

