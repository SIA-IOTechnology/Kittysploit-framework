#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sierra Wireless AceManager filteredlogs.txt disclosure (CVE-2015-6479)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sierra Wireless AceManager - Log Disclosure Detection (CVE-2015-6479)',
        'description': (
            'Detects CVE-2015-6479 by requesting /filteredlogs.txt and matching ALEOS log markers.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2015', 'sierra', 'acemanager', 'info-leak', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.2,
            'value': 0.7,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2015-6479',
        ],
        'cve': 'CVE-2015-6479',
    }

    def run(self):
        path = '/filteredlogs.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        body = r.text or ''
        if 'ALEOS_EVENTS_' in body or 'ALEOS_WAN_' in body:
            self.set_info(
                severity='medium',
                reason='AceManager filteredlogs disclosure (CVE-2015-6479)',
                path=path,
            )
            return True
        return False
