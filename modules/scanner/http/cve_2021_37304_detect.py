#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An Insecure Permissions issue in jeecg-boot 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jeecg Boot <= 2.4.5 - Information Disclosure Detection',
        'description': 'An Insecure Permissions issue in jeecg-boot 2.4.5 allows unauthenticated remote attackers to gain escalated privilege and view sensitive information via the httptrace interface.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'jeecg', 'exposure', 'vuln'],
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
            'https://github.com/jeecgboot/jeecg-boot/issues/2793',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-37304',
        ],
        'cve': 'CVE-2021-37304',
    }

    def run(self):
        r = self.http_request(method="GET", path='/jeecg-boot/actuator/httptrace/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"traces":[', '"headers"', '"request":{',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Jeecg Boot <= 2.4.5 - Information Disclosure detected",
                path='/jeecg-boot/actuator/httptrace/',
            )
            return True
        return False

