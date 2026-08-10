#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Embedthis GoAhead Host header injection (CVE-2019-16645)."""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Embedthis GoAhead - Host Header Injection Detection (CVE-2019-16645)',
        'description': (
            'Detects CVE-2019-16645 by POSTing to /goform/login (and related paths) with a '
            'crafted Host header and looking for that host in Location / moved-to responses.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2019', 'goahead', 'header-injection', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/Ramikan/Vulnerabilities/blob/master/GoAhead%20Web%20server%20HTTP%20Header%20Injection',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-16645',
        ],
        'cve': 'CVE-2019-16645',
    }

    def run(self):
        host_header = f'ksploit-{secrets.token_hex(4)}.invalid'
        for path in ('/goform/login', '/config/log_off_page.htm', '/'):
            r = self.http_request(
                method='POST',
                path=path,
                data='testdata',
                headers={
                    'Host': host_header,
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                allow_redirects=False,
            )
            if not r:
                continue
            loc = r.headers.get('Location') or r.headers.get('location') or ''
            body = r.text or ''
            if host_header in loc or (
                'This document has moved to a new' in body and host_header in body
            ):
                self.set_info(
                    severity='medium',
                    reason='GoAhead Host header injection (CVE-2019-16645)',
                    path=path,
                )
                return True
        return False
