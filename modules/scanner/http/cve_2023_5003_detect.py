#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Active Directory Integration / LDAP Integration WordPress plugin before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Active Directory Integration WP Plugin < 4.1.10 - Log Disclosure Detection',
        'description': 'The Active Directory Integration / LDAP Integration WordPress plugin before 4.1.10 stores sensitive LDAP logs in a buffer file when an administrator wants to export said logs. Unfortunately, this log file is never removed, and remains accessible to any users knowing the URL to do so.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'wpscan', 'exposure', 'csv', 'ldap', 'wordpress', 'wp-plugin', 'cve2023', 'miniorange', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-5003',
            'https://wpscan.com/vulnerability/91f4e500-71f3-4ef6-9cc7-24a7c12a5748/',
        ],
        'cve': 'CVE-2023-5003',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/ldap-authentication-report.csv', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('ID', 'USERNAME', 'TIME', 'LDAP STATUS',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Active Directory Integration WP Plugin < 4.1.10 - Log Disclosure detected",
                path='/wp-content/ldap-authentication-report.csv',
            )
            return True
        return False

