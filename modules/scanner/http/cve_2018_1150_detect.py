#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NUUO NVR Peekaboo backdoor active check (CVE-2018-1150)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NUUO NVR - Peekaboo Backdoor Detection (CVE-2018-1150)',
        'description': (
            'Detects active NUUO Peekaboo backdoor (/tmp/moses) by requesting /users_xml.php '
            'unauthenticated and looking for AccountInfo XML (CVE-2018-1150).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2018', 'nuuo', 'nvr', 'backdoor', 'unauth', 'vuln',
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
            'value': 1.0,
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
                'suggested_followups': ['scanner/http/cve_2018_14933_detect'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2018-1150',
            'https://www.tenable.com/security/research/tra-2018-25',
        ],
        'cve': 'CVE-2018-1150',
    }

    def run(self):
        r = self.http_request(method='GET', path='/users_xml.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        if '<AccountInfo>' in (r.text or ''):
            self.set_info(
                severity='critical',
                reason='NUUO Peekaboo backdoor active (CVE-2018-1150)',
                path='/users_xml.php',
            )
            return True
        return False
