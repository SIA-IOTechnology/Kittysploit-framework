#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reprise License Manager (RLM) 14."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Reprise License Manager 14.2 - Authentication Bypass Detection',
        'description': 'Reprise License Manager (RLM) 14.2 does not verify authentication or authorization and allows unauthenticated users to change the password of any existing user.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'packetstorm', 'rlm', 'auth-bypass', 'reprisesoftware', 'vuln'],
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
            'https://reprisesoftware.com/admin/rlm-admin-download.php?&euagree=yes',
            'http://packetstormsecurity.com/files/165186/Reprise-License-Manager-14.2-Unauthenticated-Password-Change.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-44152',
            'https://www.reprisesoftware.com/RELEASE_NOTES',
            'https://github.com/anonymous364872/Rapier_Tool',
        ],
        'cve': 'CVE-2021-44152',
    }

    def run(self):
        r = self.http_request(method="GET", path='/goforms/menu', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('RLM Administration Commands',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="Reprise License Manager 14.2 - Authentication Bypass detected",
                path='/goforms/menu',
            )
            return True
        return False

