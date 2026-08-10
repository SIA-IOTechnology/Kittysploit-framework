#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZoneMinder /events/ directory listing disclosure (CVE-2016-10140)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ZoneMinder - /events/ Listing Detection (CVE-2016-10140)',
        'description': (
            'Detects CVE-2016-10140 by requesting /events/ and matching Apache-style '
            'Index of.*/events directory listing.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2016', 'zoneminder', 'exposure', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2016-10140',
        ],
        'cve': 'CVE-2016-10140',
    }

    def run(self):
        import re
        for path in ('/events/', '/zm/events/', '/zoneminder/events/'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            if re.search(r'<title>Index of.*/events</title>', r.text or '', re.I):
                self.set_info(
                    severity='medium',
                    reason='ZoneMinder /events/ listing (CVE-2016-10140)',
                    path=path,
                )
                return True
        return False
