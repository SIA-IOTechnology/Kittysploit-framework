#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco Smart Software Manager On-Prem is an on-premises software license management solution offered by Cisco."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cisco Smart Software Manager On-Prem Panel - Detect',
        'description': 'Cisco Smart Software Manager On-Prem is an on-premises software license management solution offered by Cisco. It enables organizations to manage and optimize their Cisco software licenses, entitlements, and usage in their local data centers, providing greater control and visibility over software assets.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'cisco', 'manager', 'login'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://www.cisco.com/c/en/us/products/collateral/cloud-systems-management/smart-software-manager-satellite/datasheet-c78-734539.html',
            'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ssm-sql-X9MmjSYh',
        ],
    }

    def run(self):
        for path in ('/', '/#/logIn?redirectURL=%2F'):
            r = self.http_request(method='GET', path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('<title>On-Prem License Workspace</title>',)
            if any(m in body for m in body_any):
                self.set_info(
                    severity='info',
                    reason='Cisco Smart Software Manager On-Prem Panel detected',
                    path=path,
                )
                return True
        return False

