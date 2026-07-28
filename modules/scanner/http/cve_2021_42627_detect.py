#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-615 devices with firmware 20."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DIR-615 - Unauthorized Access Detection',
        'description': 'D-Link DIR-615 devices with firmware 20.06 are susceptible to unauthorized access. An attacker can access the WAN configuration page wan.htm without authentication, which can lead to disclosure of WAN settings, data modification, and/or other unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'd-link', 'router', 'unauth', 'dir-615', 'roteador', 'dlink', 'vuln'],
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
            'https://github.com/sanjokkarki/D-Link-DIR-615/blob/main/CVE-2021-42627',
            'https://www.dlink.com/en/security-bulletin/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-42627',
            'http://d-link.com',
            'http://dlink.com',
        ],
        'cve': 'CVE-2021-42627',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wan.htm', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('src=\'menu.js?v="+Math.random()+"\'></scr"+"ipt>");', 'var ipv6conntype',)
        header_any = ('Virtual Web',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="D-Link DIR-615 - Unauthorized Access detected",
                path='/wan.htm',
            )
            return True
        return False

