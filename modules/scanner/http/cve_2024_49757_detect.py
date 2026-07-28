#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The open-source identity infrastructure software Zitadel allows administrators to disable the user self-regist."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zitadel - User Registration Bypass Detection',
        'description': 'The open-source identity infrastructure software Zitadel allows administrators to disable the user self-registration. Due to a missing security check in versions prior to 2.64.0, 2.63.5, 2.62.7, 2.61.4, 2.60.4, 2.59.5, and 2.58.7, disabling the "User Registration allowed" option only hid the registration button on the login page. Users could bypass this restriction by directly accessing the registration URL (/ui/login/loginname) and register a user that way. Versions 2.64.0, 2.63.5, 2.62.7, 2.61.4, 2.60.4, 2.59.5, and 2.58.7 contain a patch. No known workarounds are available.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'register', 'zitadel', 'vuln'],
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
            'https://github.com/zitadel/zitadel/releases/tag/v2.62.7',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-49757',
        ],
        'cve': 'CVE-2024-49757',
    }

    def run(self):
        r = self.http_request(method="GET", path='/ui/login/register', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('registration is not allowed (internal)',)
        body_all = ('enter your userdata', 'zitadel',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Zitadel - User Registration Bypass detected",
                path='/ui/login/register',
            )
            return True
        return False

