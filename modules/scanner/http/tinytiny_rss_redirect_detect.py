#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected an open redirect vulnerability in Tiny Tiny RSS where the return parameter in public."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TinyTiny RSS Open Redirect Detection',
        'description': 'Detected an open redirect vulnerability in Tiny Tiny RSS where the return parameter in public.php was abused to redirect users to an attacker-controlled external URL after the authentication flow.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'vulnerability', 'redirect', 'tiny-tiny', 'rss'],
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
        'references': ['https://seclists.org/oss-sec/2019/q1/155'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/public.php?return=http%3a%2f%2finteract.sh%2f&op=login&login=password=&profile=0', allow_redirects=False)
        if not r or r.status_code not in (302, 301):
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='low',
                reason="TinyTiny RSS Open Redirect detected",
                path='/public.php?return=http%3a%2f%2finteract.sh%2f&op=login&login=password=&profile=0',
            )
            return True
        return False

