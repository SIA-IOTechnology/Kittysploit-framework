#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Thinfinity VirtualUI (before v3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Thinfinity VirtualUI User Enumeration Detection',
        'description': 'Thinfinity VirtualUI (before v3.0), /changePassword returns different responses for requests depending on whether the username exists. It may enumerate OS users (Administrator, Guest, etc.)',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'exposure', 'thinfinity', 'packetstorm', 'virtualui', 'tenable', 'cybelesoft', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/cybelesoft/virtualui/issues/1',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-44848',
            'https://www.tenable.com/cve/CVE-2021-44848',
            'http://packetstormsecurity.com/files/165327/Cibele-Thinfinity-VirtualUI-2.5.41.0-User-Enumeration.html',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-44848',
    }

    def run(self):
        path = '/changePassword?username=administrator'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('"rc":(.*?)', '"msg":"(.*?)"',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='medium', reason='Thinfinity VirtualUI User Enumeration detected', path=path)
            return True
        return False

