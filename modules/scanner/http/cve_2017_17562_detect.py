#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Embedthis GoAhead CGI environment injection (CVE-2017-17562)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GoAhead - CGI LD_DEBUG Injection Detection (CVE-2017-17562)',
        'description': (
            'Detects CVE-2017-17562 by POSTing to common CGI endpoints with ?LD_DEBUG=help '
            'and looking for dynamic linker help output.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'goahead', 'rce', 'cgi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 8,
            'reversible': True,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-17562',
            'https://www.elttam.com/blog/goahead/',
        ],
        'cve': 'CVE-2017-17562',
    }

    ENDPOINTS = (
        '/cgi-bin/login', '/cgi-bin/index', '/cgi-bin/admin', '/cgi-bin/webproc',
        '/cgi-bin/cgitest', '/cgi/login', '/cgi-bin/login.cgi', '/cgi-bin/index.cgi',
        '/cgi-bin/apply', '/cgi-bin/config', '/cgi-bin/firmware', '/cgi-bin/status',
    )

    def run(self):
        markers = (
            ' LD_DEBUG_OUTPUT ',
            'valid options for the ld_debug environment variable are:',
        )
        for ep in self.ENDPOINTS:
            path = ep + '?LD_DEBUG=help'
            r = self.http_request(method='POST', path=path, data='', allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if any(m in body for m in markers):
                self.set_info(
                    severity='critical',
                    reason='GoAhead CGI env injection (CVE-2017-17562)',
                    path=ep,
                )
                return True
        return False
