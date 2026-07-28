#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JumpServer is an open source bastion host and an operation and maintenance security audit system."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JumpServer - Open Redirect via Referer Header Detection',
        'description': 'JumpServer is an open source bastion host and an operation and maintenance security audit system. Prior to v3.10.19 and v4.10.5, The /core/i18n// endpoint uses the Referer header as the redirection target without proper validation, which could lead to an Open Redirect vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'jumpserver', 'redirect', 'open-redirect', 'fit2cloud'],
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
            'https://github.com/jumpserver/jumpserver/security/advisories/GHSA-h762-mj7p-jwjq',
            'https://github.com/jumpserver/jumpserver/commit/36ae076cb021f16d2053a63651bc16d15a3ed53b',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-58044',
        ],
        'cve': 'CVE-2025-58044',
    }

    def run(self):
        r = self.http_request(method="GET", path='/core/i18n/ko/', allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?i)location:\\s*https?://oast\\.pro',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="JumpServer - Open Redirect via Referer Header detected",
                path='/core/i18n/ko/',
            )
            return True
        return False

