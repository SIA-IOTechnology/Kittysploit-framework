#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability has been found in D-Link DNS-320L, DNS-320LW and DNS-327L up to 20240403 and classified as pro."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-LINK DNS-320L,DNS-320LW and DNS-327L - Information Disclosure Detection',
        'description': 'A vulnerability has been found in D-Link DNS-320L, DNS-320LW and DNS-327L up to 20240403 and classified as problematic. Affected by this vulnerability is an unknown functionality of the file /cgi-bin/info.cgi of the component HTTP GET Request Handler.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'dlink', 'exposure', 'vuln'],
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
            'https://github.com/netsecfish/info_cgi',
            'https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10383',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-3274',
        ],
        'cve': 'CVE-2024-3274',
    }

    def run(self):
        path = '/cgi-bin/info.cgi'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Model=', 'Build=', 'Macaddr=',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='D-LINK DNS-320L,DNS-320LW and DNS-327L - Information Disclosure detected', path=path)
            return True
        return False

