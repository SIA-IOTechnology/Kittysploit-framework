#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AntD Admin has a security vulnerability that stems from Antd-admin 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AntD Admin - Sensitive Information Disclosure Detection',
        'description': 'AntD Admin has a security vulnerability that stems from Antd-admin 5.5.0 being affected by an incorrect access control vulnerability. Attackers can exploit this vulnerability to gain unauthorized access to some front-end interfaces, resulting in the leakage of sensitive information such as user IDs, names, ages, phone numbers, addresses, and more.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'antdadmin', 'disclosure'],
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
            'https://github.com/zuiidea/antd-admin/issues/1127',
            'https://github.com/zuiidea/antd-admin',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-46371',
        ],
        'cve': 'CVE-2021-46371',
    }

    def run(self):
        path = '/api/v1/users'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('email":', 'data":[{"id":', 'phone":"',)
        ctype_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='high',
                reason='AntD Admin - Sensitive Information Disclosure detected',
                path=path,
            )
            return True
        return False

