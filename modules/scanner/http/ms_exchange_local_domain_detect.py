#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microsoft Exchange is prone to a local domain exposure using the Autodiscover v2 endpoint."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microsoft Exchange Autodiscover - Local Domain Exposure Detection',
        'description': 'Microsoft Exchange is prone to a local domain exposure using the Autodiscover v2 endpoint.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'microsoft', 'ms-exchange', 'ad', 'dc', 'vuln'],
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
            'https://support.microsoft.com/en-gb/topic/autodiscover-v2-returns-internalurl-not-externalurls-in-other-site-774301e2-2d1e-d5e0-aa41-a49f6e9b06f4',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/autodiscover/autodiscover.json?Protocol=ActiveSync&Email=user@domain.tld&RedirectCount=1', allow_redirects=False)
        if not r or r.status_code not in (200, 302):
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?i)(X-Calculatedbetarget:)',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='info',
                reason="Microsoft Exchange Autodiscover - Local Domain Exposure detected",
                path='/autodiscover/autodiscover.json?Protocol=ActiveSync&Email=user@domain.tld&RedirectCount=1',
            )
            return True
        return False

