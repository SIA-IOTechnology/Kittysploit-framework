#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Alerta prior to version 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Alerta < 8.1.0 - Authentication Bypass Detection',
        'description': 'Alerta prior to version 8.1.0 is prone to authentication bypass when using LDAP as an authorization provider and the LDAP server accepts Unauthenticated Bind requests.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'alerta', 'auth-bypass', 'alerta_project', 'passive', 'vuln'],
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
            'https://github.com/advisories/GHSA-5hmm-x8q8-w5jh',
            'https://tools.ietf.org/html/rfc4513#section-5.1.2',
            'https://pypi.org/project/alerta-server/8.1.0/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-26214',
            'https://github.com/alerta/alerta/commit/2bfa31779a4c9df2fa68fa4d0c5c909698c5ef65',
        ],
        'cve': 'CVE-2020-26214',
    }

    def run(self):
        path = '/api/config'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"alarm_model"', '"actions"', '"severity"',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='critical',
                reason='Alerta < 8.1.0 - Authentication Bypass detected',
                path=path,
            )
            return True
        return False

