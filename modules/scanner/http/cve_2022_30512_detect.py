#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""School Dormitory Management System 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'School Dormitory Management System 1.0 - SQL Injection Detection',
        'description': 'School Dormitory Management System 1.0 contains a SQL injection vulnerability via accounts/payment_history.php:31. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'sqli', 'school_dormitory_management_system_project', 'vuln'],
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
            'https://github.com/bigzooooz/CVE-2022-30512',
            'https://www.sourcecodester.com/php/15319/school-dormitory-management-system-phpoop-free-source-code.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-30512',
            'https://github.com/SYRTI/POC_to_review',
            'https://github.com/WhooAmii/POC_to_review',
        ],
        'cve': 'CVE-2022-30512',
    }

    def run(self):
        r = self.http_request(method="GET", path='/dms/admin/accounts/payment_history.php?account_id=2%27', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('Fatal error', 'Uncaught Error: Call to a member function fetch_assoc()', '<th class="">Month of</th>',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="School Dormitory Management System 1.0 - SQL Injection detected",
                path='/dms/admin/accounts/payment_history.php?account_id=2%27',
            )
            return True
        return False

