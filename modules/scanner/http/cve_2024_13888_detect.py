#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The WPMobile."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WPMobile.App <= 11.56 - Open Redirect Detection',
        'description': "The WPMobile.App plugin for WordPress is vulnerable to Open Redirect in all versions up to, and including, 11.56. This is due to insufficient validation on the redirect URL supplied via the 'redirect' parameter. This makes it possible for unauthenticated attackers to redirect users to potentially malicious sites if they can successfully trick them into performing an action.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'redirect', 'wp', 'wordpress', 'wp-plugin', 'wpappninja', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wpappninja/wpmobileapp-1156-open-redirect-via-redirect-parameter',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-13888',
        ],
        'cve': 'CVE-2024-13888',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('wpappninja',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/?redirect=aHR0cDovL29hc3QubWU=&WPMOBILE_LOCALE=en'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.me\\/?(\\/|[^.].*)?$',)
        if any(re.search(rx, headers) for rx in header_regexes):
            self.set_info(severity='high', reason='WPMobile.App <= 11.56 - Open Redirect detected', path=path)
            return True
        return False

