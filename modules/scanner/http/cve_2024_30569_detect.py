#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Netgear R6850 router firmware version V1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Netgear R6850 - Information Disclosure Detection',
        'description': 'Netgear R6850 router firmware version V1.1.0.88 contains an information leakage vulnerability in the currentsetting.htm page.This hidden interface is not protected by authentication, allowing unauthenticated attackers to access sensitive informationsuch as firmware version, model details, connection status, and other system configuration data.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'netgear', 'router', 'exposure', 'vuln'],
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
            'https://github.com/funny-mud-peee/IoT-vuls/blob/main/netgear%20R6850/Info%20Leak%20in%20Netgear-R6850%EF%BC%88currentsetting.htm%EF%BC%89.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-30569',
            'https://www.netgear.com/about/security/',
        ],
        'cve': 'CVE-2024-30569',
    }

    def run(self):
        r = self.http_request(method="GET", path='/currentsetting.htm', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Firmware=', 'LoginMethod=', 'Model=',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Netgear R6850 - Information Disclosure detected",
                path='/currentsetting.htm',
            )
            return True
        return False

