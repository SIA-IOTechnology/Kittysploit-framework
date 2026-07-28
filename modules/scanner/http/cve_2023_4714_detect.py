#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability was found in PlayTube 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PlayTube 3.0.1 - Information Disclosure Detection',
        'description': 'A vulnerability was found in PlayTube 3.0.1 and classified as problematic. This issue affects some unknown processing of the component Redirect Handler. The manipulation leads to information disclosure. The attack may be initiated remotely.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'playtube', 'exposure', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-4714',
            'https://www.exploitalert.com/view-details.html?id=39826',
            'https://vuldb.com/?ctiid.238577',
            'https://vuldb.com/?id.238577',
            'https://github.com/Threekiii/Awesome-POC',
        ],
        'cve': 'CVE-2023-4714',
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('razorpay_options', 'PlayTube', 'key:',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="PlayTube 3.0.1 - Information Disclosure detected",
                path='/',
            )
            return True
        return False

