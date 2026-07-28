#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple systems of Hangzhou Jila Technology Co."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LVS Lean Value Management System Business - Directory Listing Detection',
        'description': 'Multiple systems of Hangzhou Jila Technology Co., Ltd. have been found to have directory traversal vulnerabilities. These vulnerabilities arise from the inadequate access controls implemented in the /Business/ directory. Malicious actors can potentially leverage these vulnerabilities to illicitly access sensitive information.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'vulnerability', 'lean-value', 'misconfig', 'listing', 'vuln'],
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
            'https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E5%90%89%E6%8B%89%E7%A7%91%E6%8A%80%20LVS%E7%B2%BE%E7%9B%8A%E4%BB%B7%E5%80%BC%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%20Business%20%E7%9B%AE%E5%BD%95%E9%81%8D%E5%8E%86%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/Business/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('/Business/', 'AgencytaskList.aspx',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="LVS Lean Value Management System Business - Directory Listing detected",
                path='/Business/',
            )
            return True
        return False

