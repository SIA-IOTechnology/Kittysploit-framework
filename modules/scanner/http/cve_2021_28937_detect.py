#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Acexy Wireless-N WiFi Repeater REV 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Acexy Wireless-N WiFi Repeater REV 1.0 - Repeater Password Disclosure Detection',
        'description': 'Acexy Wireless-N WiFi Repeater REV 1.0 is vulnerable to password disclosure because the password.html page of the web management interface contains the administrator account password in plaintext.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'acexy', 'disclosure', 'iot', 'vuln'],
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
            'https://blog-ssh3ll.medium.com/acexy-wireless-n-wifi-repeater-vulnerabilities-8bd5d14a2990',
            'http://acexy.com',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-28937',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-28937',
    }

    def run(self):
        r = self.http_request(method="GET", path='/password.html', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Password Setting', "addCfg('username'", "addCfg('newpass'",)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Acexy Wireless-N WiFi Repeater REV 1.0 - Repeater Password Disclosure detected",
                path='/password.html',
            )
            return True
        return False

