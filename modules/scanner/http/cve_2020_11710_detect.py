#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kong Admin through 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kong Admin <=2.03 - Admin API Access Detection',
        'description': 'Kong Admin through 2.0.3 contains an issue via docker-kong which makes the admin API port accessible on interfaces other than 127.0.0.1.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'kong', 'konghq', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2020-11710',
            'https://github.com/Kong/kong',
            'https://github.com/Kong/docs.konghq.com/commit/d693827c32144943a2f45abc017c1321b33ff611',
            'https://github.com/Kong/docker-kong/commit/dfa095cadf7e8309155be51982d8720daf32e31c',
            'https://github.com/Kong/docs.konghq.com/commit/e99cf875d875dd84fdb751079ac37882c9972949',
        ],
        'cve': 'CVE-2020-11710',
    }

    def run(self):
        for path in ('/', '/admin/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('Welcome to kong', 'configuration', 'kong_env',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='critical',
                    reason="Kong Admin <=2.03 - Admin API Access detected",
                    path=path,
                )
                return True
        return False

