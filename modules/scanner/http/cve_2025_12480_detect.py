#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Gladinet Triofox solution before 12."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Triofox - Improper Access Control Detection',
        'description': 'The Gladinet Triofox solution before 12.91.1126.65588 and CentreStack before 12.10.595.65696 allow unauthenticated access to the /management/admindatabase.aspx endpoint, exposing sensitive database management functionality to anyone with network access. An unauthenticated attacker can remotely access, view, and potentially interact with the database management interface, risking data disclosure or system compromise.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'triofox', 'unauth', 'exposure', 'vkev', 'kev'],
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
            'https://cloud.google.com/blog/topics/threat-intelligence/triofox-vulnerability-cve-2025-12480',
            'https://attackerkb.com/topics/5C4wRy6hY7/cve-2025-12480/rapid7-analysis',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-12480',
        ],
        'cve': 'CVE-2025-12480',
    }

    def run(self):
        path = '/management/admindatabase.aspx'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Triofox Enterprise', 'Manage Database', 'Configure Database',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Triofox - Improper Access Control detected', path=path)
            return True
        return False

