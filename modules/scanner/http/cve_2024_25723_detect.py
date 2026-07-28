#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZenML Server in the ZenML machine learning package before 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ZenML ZenML Server - Improper Authentication Detection',
        'description': 'ZenML Server in the ZenML machine learning package before 0.46.7 for Python allows remote privilege escalation because the /api/v1/users/{user_name_or_id}/activate REST API endpoint allows access on the basis of a valid username along with a new password in the request body.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'passive', 'auth-bypass', 'zenml', 'vuln'],
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
            'https://www.zenml.io/blog/critical-security-update-for-zenml-users',
            'https://github.com/zenml-io/zenml',
            'https://github.com/zenml-io/zenml/compare/0.42.1...0.42.2',
            'https://github.com/zenml-io/zenml/compare/0.43.0...0.43.1',
            'https://github.com/zenml-io/zenml/compare/0.44.3...0.44.4',
        ],
        'cve': 'CVE-2024-25723',
    }

    def run(self):
        path = '/api/v1/info'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('0.44.4', '0.43.1', '0.42.2',)
        body_all = ('deployment_type', 'database_type',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason='ZenML ZenML Server - Improper Authentication detected',
                path=path,
            )
            return True
        return False

