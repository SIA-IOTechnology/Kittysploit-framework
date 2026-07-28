#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CasaOS is an open-source Personal Cloud system."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CasaOS  < 0.4.4 - Authentication Bypass via Random JWT Token Detection',
        'description': "CasaOS is an open-source Personal Cloud system. Unauthenticated attackers can craft arbitrary JWTs and access features that usually require authentication and execute arbitrary commands as `root` on CasaOS instances. This problem was addressed by improving the validation of JWTs in commit `705bf1f`. This patch is part of CasaOS 0.4.4. Users should upgrade to CasaOS 0.4.4. If they can't, they should temporarily restrict access to CasaOS to untrusted users, for instance by not exposing it publicly.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'oss', 'casaos', 'jwt', 'icewhale', 'vuln'],
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
            'https://github.com/IceWhaleTech/CasaOS/commit/705bf1facbffd2ca40b159b0303132b6fdf657ad',
            'https://github.com/IceWhaleTech/CasaOS/security/advisories/GHSA-m5q5-8mfw-p2hr',
        ],
        'cve': 'CVE-2023-37266',
    }

    def run(self):
        r = self.http_request(method="GET", path='/v1/folder?path=%2F', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"success":200', '"message":"ok"', 'content', 'is_dir',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="CasaOS  < 0.4.4 - Authentication Bypass via Random JWT Token detected",
                path='/v1/folder?path=%2F',
            )
            return True
        return False

