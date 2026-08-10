#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vBulletin install/upgrade.php authentication bypass exposure (CVE-2013-6129)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'vBulletin - install/upgrade.php Exposure Detection (CVE-2013-6129)',
        'description': (
            'Detects CVE-2013-6129 style install exposure by finding reachable '
            '/install/upgrade.php with Customer Number form.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2013', 'vbulletin', 'auth-bypass', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.2,
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2013-6129',
        ],
        'cve': 'CVE-2013-6129',
    }

    def run(self):
        for base in ('', '/forum', '/vb', '/vbulletin'):
            for mid in ('', '/core'):
                path = f'{base}{mid}/install/upgrade.php'
                r = self.http_request(method='GET', path=path, allow_redirects=False)
                if not r or r.status_code != 200:
                    continue
                body = r.text or ''
                if 'vBulletin' in body and 'Customer Number' in body:
                    self.set_info(
                        severity='critical',
                        reason='vBulletin install/upgrade.php exposed (CVE-2013-6129)',
                        path=path,
                    )
                    return True
        return False
