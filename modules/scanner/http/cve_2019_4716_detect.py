#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IBM Planning Analytics versions 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IBM Planning Analytics - Authentication Bypass & Remote Code Execution Version Detection',
        'description': 'IBM Planning Analytics versions 2.0.0 through 2.0.8 are vulnerable to a configuration overwrite that allows an unauthenticated user to login as "admin", and then execute code as root or SYSTEM via TM1 scripting.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'ibm', 'planning_analytics', 'passive', 'kev', 'vkev'],
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
            'https://www.ibm.com/support/pages/node/1127781',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-4716',
            'http://packetstormsecurity.com/files/156953/IBM-Cognos-TM1-IBM-Planning-Analytics-Server-Configuration-Overwrite-Code-Execution.html',
        ],
        'cve': 'CVE-2019-4716',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('IBM Planning Analytics', 'IBM Cognos TM1',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='IBM Planning Analytics - Authentication Bypass & Remote Code Execution Version detected',
                path=path,
            )
            return True
        return False

