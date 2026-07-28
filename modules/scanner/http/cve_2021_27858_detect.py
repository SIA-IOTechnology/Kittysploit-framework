#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FatPipe WARP, IPVPN, and MPVPN software prior to versions 10."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FatPipe WARP/IPVPN/MPVPN - Authorization Bypass Detection',
        'description': 'FatPipe WARP, IPVPN, and MPVPN software prior to versions 10.1.2r60p91 and 10.2.2r42 contain a missing authorization caused by lack of access control in the web management interface, letting remote attackers access sensitive URLs, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'fatpipe', 'auth-bypass', 'router', 'vuln'],
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
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5682.php',
            'https://www.fatpipeinc.com/support/advisories.php',
            'https://www.fatpipeinc.com/support/cve-list.php',
            'https://www.zeroscience.mk/codes/fatpipe_auth.txt',
        ],
        'cve': 'CVE-2021-27858',
    }

    def run(self):
        path = '/fpui/jsp/index.jsp'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept': '*/*'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('productType', 'type:', 'version:', '<title>FatPipe Networks</title>',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='FatPipe WARP/IPVPN/MPVPN - Authorization Bypass detected', path=path)
            return True
        return False

