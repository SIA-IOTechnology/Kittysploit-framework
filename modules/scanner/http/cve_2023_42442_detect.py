#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JumpServer is an open source bastion host and a professional operation and maintenance security audit system."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JumpServer > 3.6.4 - Information Disclosure Detection',
        'description': 'JumpServer is an open source bastion host and a professional operation and maintenance security audit system. Starting in version 3.0.0 and prior to versions 3.5.5 and 3.6.4, session replays can download without authentication. Session replays stored in S3, OSS, or other cloud storage are not affected. The api `/api/v1/terminal/sessions/` permission control is broken and can be accessed anonymously. SessionViewSet permission classes set to `[RBACPermission | IsSessionAssignee]`, relation is or, so any permission matched will be allowed. Versions 3.5.5 and 3.6.4 have a fix. After upgrading, visit the api `$HOST/api/v1/terminal/sessions/?limit=1`. The expected http response code is 401 (`not_authenticated`).',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'jumpserver', 'exposure', 'fit2cloud', 'vuln'],
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
            'https://github.com/jumpserver/jumpserver/blob/v3.6.1/apps/terminal/api/session/session.py#L91',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-42442',
            'https://github.com/jumpserver/jumpserver/commit/0a58bba59cd275bab8e0ae58bf4b359fbc5eb74a',
            'https://github.com/Marco-zcl/POC',
            'https://github.com/nomi-sec/PoC-in-GitHub',
        ],
        'cve': 'CVE-2023-42442',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/v1/terminal/sessions/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"terminal":', '"user_id":"', '"account_id":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="JumpServer > 3.6.4 - Information Disclosure detected",
                path='/api/v1/terminal/sessions/',
            )
            return True
        return False

