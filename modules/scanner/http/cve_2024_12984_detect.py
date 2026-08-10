#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Amcrest IP camera webCapsConfig information disclosure (CVE-2024-12984)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Amcrest IP Camera - webCapsConfig Information Disclosure (CVE-2024-12984)',
        'description': (
            'Amcrest IP cameras expose /web_caps/webCapsConfig without authentication, '
            'disclosing deviceType and WebVersion metadata.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2024', 'amcrest', 'camera', 'iot',
            'exposure', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['scanner/http/amcrest_detect'],
            },
        },
        'references': [
            'https://netsecfish.notion.site/AMCREST-IP-Camera-Information-Disclosure-1596b683e67c8045ad10c16b3eed456f',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-12984',
        ],
        'cve': 'CVE-2024-12984',
    }

    def run(self):
        path = '/web_caps/webCapsConfig'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if '"deviceType"' in body and '"WebVersion"' in body:
            self.set_info(
                severity='medium',
                reason='Amcrest CVE-2024-12984 webCapsConfig information disclosure',
                path=path,
            )
            return True
        return False
