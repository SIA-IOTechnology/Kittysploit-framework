#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RStudio Connect prior to 2023."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'RStudio Connect - Open Redirect Detection',
        'description': 'RStudio Connect prior to 2023.01.0 is affected by an Open Redirect issue. The vulnerability could allow an attacker to redirect users to malicious websites.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'tenable', 'cve', 'cve2022', 'redirect', 'rstudio', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://tenable.com/security/research/tra-2022-30',
            'https://support.posit.co/hc/en-us/articles/10983374992023-CVE-2022-38131-configuration-issue-in-Posit-Connect',
            'https://github.com/JoshuaMart/JoshuaMart',
        ],
        'cve': 'CVE-2022-38131',
    }

    def run(self):
        path = '//%5coast.me'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 307:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)?(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.me\\/?(\\/|[^.].*)?$',)
        if any(re.search(rx, headers) for rx in header_regexes):
            self.set_info(severity='medium', reason='RStudio Connect - Open Redirect detected', path=path)
            return True
        return False

