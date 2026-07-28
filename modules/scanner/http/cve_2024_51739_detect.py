#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""From the webservices/rest."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'iTop - User Enumeration via REST Endpoint Detection',
        'description': 'From the webservices/rest.php file, several operations are accessible from an unauthenticated user. One of them is `do_reset_pwd`, allowing to reset a user password. This feature can be abused to perform user enumeration when a non-existent user is provided.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'itop', 'enum', 'unauth', 'vuln'],
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
            'https://www.synacktiv.com/en/advisories/multiple-vulnerabilities-on-itop',
            'https://github.com/Combodo/iTop/security/advisories/GHSA-2hmf-p27w-phf9',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-51739',
        ],
        'cve': 'CVE-2024-51739',
    }

    def run(self):
        r = self.http_request(method="GET", path='/webservices/rest.php?loginop=do_reset_pwd&auth_user=doesnotexist', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<h1>Reset password</h1>', '&#039;doesnotexist&#039; is not a valid login',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="iTop - User Enumeration via REST Endpoint detected",
                path='/webservices/rest.php?loginop=do_reset_pwd&auth_user=doesnotexist',
            )
            return True
        return False

