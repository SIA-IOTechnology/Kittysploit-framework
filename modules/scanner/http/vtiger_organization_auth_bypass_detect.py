#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects vtiger <= 5."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'vtiger CRM - graph.php OrganizationConfig Auth Bypass Detection',
        'description': (
            'Detects vtiger <= 5.2.1 auth bypass by requesting graph.php?module=Settings&action=OrganizationConfig and matching Company Details.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vtiger', 'auth-bypass', 'unauth', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.securityfocus.com/bid/51192',
        ],
    }

    def run(self):
        suffix = '/graph.php?module=Settings&action=OrganizationConfig&parenttab=Settings'
        for base in ('', '/vtiger', '/crm', '/vtigercrm'):
            path = f'{base}{suffix}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            body = (r.text or '') if r else ''
            # Greenbone: Company Details + EditCompanyDetails + Company Name
            if (
                'Company Details' in body
                and 'EditCompanyDetails' in body
                and 'Company Name' in body
            ):
                self.set_info(
                    severity='high',
                    reason='vtiger CRM graph.php OrganizationConfig auth bypass',
                    path=f'{base}/graph.php',
                )
                return True
        return False

