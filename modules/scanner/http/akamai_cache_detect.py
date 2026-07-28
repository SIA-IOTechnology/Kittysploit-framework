#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sends a HEAD request with a Pragma header value of "akamai-x-cache-on" and looks for an akamai-specific respon."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Akamai Cache Detection',
        'description': 'Sends a HEAD request with a Pragma header value of "akamai-x-cache-on" and looks for an akamai-specific response header value.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'cache', 'akamai', 'tech'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://community.akamai.com/customers/s/article/Using-Akamai-Pragma-headers-to-investigate-or-troubleshoot-Akamai-content-delivery?language=en_US',
            'https://spyclub.tech/2022/12/14/unusual-cache-poisoning-akamai-s3/',
        ],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='HEAD', path=path, allow_redirects=False, headers={'Pragma': 'akamai-x-cache-on'})
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?:TCP_HIT|TCP_MISS).*deploy\\.akamaitechnologies\\.com',)
        if any(re.search(rx, headers) for rx in header_regexes):
            self.set_info(
                severity='info',
                reason='Akamai Cache detected',
                path=path,
            )
            return True
        return False

