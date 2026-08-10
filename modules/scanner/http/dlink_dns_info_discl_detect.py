#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DNS devices unauthenticated info disclosure CGIs."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DNS - Info Disclosure CGI Detection',
        'description': (
            'Detects unauthenticated info disclosure on D-Link DNS via '
            '/cgi-bin/info.cgi, discovery.cgi, or status_mgr.cgi.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'dlink', 'nas', 'info-disclosure', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.2,
            'value': 0.7,
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/37142',
        ],
    }

    def run(self):
        checks = (
            ('/cgi-bin/info.cgi', 'Product='),
            ('/cgi-bin/discovery.cgi', '<entry>'),
            ('/cgi-bin/status_mgr.cgi?cmd=cgi_get_status', '<status>'),
        )
        for path, marker in checks:
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and marker in (r.text or ''):
                self.set_info(
                    severity='medium',
                    reason='D-Link DNS info disclosure CGI',
                    path=path.split('?')[0],
                )
                return True
        return False
