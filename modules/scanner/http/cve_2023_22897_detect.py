#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue was discovered in SecurePoint UTM before 12."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Securepoint UTM - Leaking Remote Memory Contents Detection',
        'description': "An issue was discovered in SecurePoint UTM before 12.2.5.1. The firewall's endpoint at /spcgi.cgi allows information disclosure of memory contents to be achieved by an authenticated user. Essentially, uninitialized data can be retrieved via an approach in which a sessionid is obtained but not used.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'securepoint', 'utm', 'exposure', 'memory', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-22897',
            'https://github.com/MrTuxracer/advisories/blob/master/CVEs/CVE-2023-22897.txt',
            'https://www.rcesecurity.com/2023/04/securepwn-part-2-leaking-remote-memory-contents-cve-2023-22897/',
            'https://rcesecurity.com',
            'https://github.com/MrTuxracer/advisories',
        ],
        'cve': 'CVE-2023-22897',
    }

    def run(self):
        path = '/spcgi.cgi'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"sessionid":', '"mode":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Securepoint UTM - Leaking Remote Memory Contents detected', path=path)
            return True
        return False

