#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sophos Firewall version v18."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sophos Firewall <=18.5 MR3 - Remote Code Execution Detection',
        'description': 'Sophos Firewall version v18.5 MR3 and older contains an authentication bypass vulnerability in the User Portal and Webadmin which could allow a remote attacker to execute code.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'sophos', 'firewall', 'auth-bypass', 'rce', 'kev', 'vkev', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/killvxk/CVE-2022-1040',
            'https://github.com/CronUp/Vulnerabilidades/blob/main/CVE-2022-1040_checker',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1040',
            'https://www.sophos.com/en-us/security-advisories/sophos-sa-20220325-sfos-rce',
            'https://github.com/Mr-xn/Penetration_Testing_POC',
        ],
        'cve': 'CVE-2022-1040',
    }

    def run(self):
        path = '/userportal/Controller?mode=8700&operation=1&datagrid=179&json={"🦞":"test"}'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'X-Requested-With': 'XMLHttpRequest'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('{"status":"Session Expired"}',)
        header_any = ('Server: xxxx',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason='Sophos Firewall <=18.5 MR3 - Remote Code Execution detected',
                path=path,
            )
            return True
        return False

