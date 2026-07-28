#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Akkadian Provisioning Manager is susceptible to information disclosure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Akkadian Provisioning Manager - Information Disclosure Detection',
        'description': 'Akkadian Provisioning Manager is susceptible to information disclosure. The restricted shell provided can be escaped by abusing the Edit MySQL Configuration command. This command launches a standard VI editor interface which can then be escaped.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'akkadian', 'mariadb', 'disclosure', 'akkadianlabs', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://threatpost.com/unpatched-bugs-provisioning-cisco-uc/166882/',
            'https://www.rapid7.com/blog/post/2021/06/08/akkadian-provisioning-manager-multiple-vulnerabilities-disclosure/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-31581',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-31581',
    }

    def run(self):
        r = self.http_request(method="GET", path='/pme/database/pme/phinx.yml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('html>',)
        body_all = ('host:', 'name:', 'pass:',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Akkadian Provisioning Manager - Information Disclosure detected",
                path='/pme/database/pme/phinx.yml',
            )
            return True
        return False

