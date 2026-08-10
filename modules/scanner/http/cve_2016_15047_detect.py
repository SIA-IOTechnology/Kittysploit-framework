#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AVTECH devices unauthenticated capability disclosure (CVE-2016-15047 family)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AVTECH - Machine.cgi Capability Disclosure Detection',
        'description': (
            'Detects AVTECH unauthenticated information disclosure via '
            '/cgi-bin/nobody/Machine.cgi?action=get_capability.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2016', 'avtech', 'camera', 'info-leak', 'unauth', 'vuln',
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
            'value': 0.8,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2016-15047',
        ],
        'cve': 'CVE-2016-15047',
    }

    def run(self):
        path = '/cgi-bin/nobody/Machine.cgi?action=get_capability'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        body = r.text or ''
        if (
            'Firmware.Version=' in body
            and 'MACAddress=' in body
            and 'Product.Type=' in body
            and 'Audio.DownloadFormat=' in body
        ):
            self.set_info(
                severity='medium',
                reason='AVTECH Machine.cgi capability disclosure',
                path=path,
            )
            return True
        return False
