#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dispatcher before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adobe AEM Dispatcher <4.15 - Rules Bypass Detection',
        'description': 'Dispatcher before 4.1.5 in Adobe Experience Manager 5.6.1, 6.0.0, and 6.1.0 does not properly implement a URL filter, which allows remote attackers to bypass dispatcher rules via unspecified vectors.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2016', 'adobe', 'aem', 'vuln'],
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
            'https://www.kernelpicnic.net/2016/07/24/Microsoft-signout.live.com-Remote-Code-Execution-Write-Up.html',
            'https://helpx.adobe.com/security/products/experience-manager/apsb16-05.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2016-0957',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2016-0957',
    }

    def run(self):
        r = self.http_request(method="GET", path='/system/console?.css', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Adobe', 'java.lang', '(Runtime)',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Adobe AEM Dispatcher <4.15 - Rules Bypass detected",
                path='/system/console?.css',
            )
            return True
        return False

