#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ifw8 Router ROM v4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ifw8 Router ROM v4.31 - Credential Discovery Detection',
        'description': 'ifw8 Router ROM v4.31 is vulnerable to credential disclosure via action/usermanager.htm HTML source code.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'exposure', 'router', 'iot', 'ifw8', 'vuln'],
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
            'https://github.com/Mr-xn/Penetration_Testing_POC/blob/master/CVE-2019-16313%20%E8%9C%82%E7%BD%91%E4%BA%92%E8%81%94%E4%BC%81%E4%B8%9A%E7%BA%A7%E8%B7%AF%E7%94%B1%E5%99%A8v4.31%E5%AF%86%E7%A0%81%E6%B3%84%E9%9C%B2%E6%BC%8F%E6%B4%9E.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-16313',
            'http://www.iwantacve.cn/index.php/archives/311/',
            'https://github.com/CnHack3r/Penetration_PoC',
            'https://github.com/apachecn-archive/Middleware-Vulnerability-detection',
        ],
        'cve': 'CVE-2019-16313',
    }

    def run(self):
        r = self.http_request(method="GET", path='/action/usermanager.htm', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('<td class="pwd" data="([a-z]+)">\\*\\*\\*\\*\\*\\*<\\/td>',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="ifw8 Router ROM v4.31 - Credential Discovery detected",
                path='/action/usermanager.htm',
            )
            return True
        return False

