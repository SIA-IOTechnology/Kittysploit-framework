#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QiHang Media Web Digital Signage 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'QiHang Media Web Digital Signage 3.0.9 - Cleartext Credentials Disclosure Detection',
        'description': 'QiHang Media Web Digital Signage 3.0.9 suffers from a clear-text credentials disclosure vulnerability that allows an unauthenticated attacker to issue a request to an unprotected directory that hosts an XML file /xml/User/User.xml and obtain administrative login information that allows for a successful authentication bypass attack.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'qihang', 'exposure', 'vuln'],
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
        'references': ['https://www.zeroscience.mk/en/vulnerabilities/ZSL-2020-5579.php'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/xml/User/User.xml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<?xml version', '<Users>', 'account=', 'password=',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="QiHang Media Web Digital Signage 3.0.9 - Cleartext Credentials Disclosure detected",
                path='/xml/User/User.xml',
            )
            return True
        return False

