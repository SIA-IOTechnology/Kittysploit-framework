#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Flarum is open source discussion platform software."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Flarum < 1.8.5 - Open Redirect Detection',
        'description': 'Flarum is open source discussion platform software. Prior to version 1.8.5, the Flarum `/logout` route includes a redirect parameter that allows any third party to redirect users from a (trusted) domain of the Flarum installation to redirect to any link. For logged-in users, the logout must be confirmed. Guests are immediately redirected. This could be used by spammers to redirect to a web address using a trusted domain of a running Flarum installation.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'flarum', 'redirect', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
                'min_params': 0,
                'tech_hints_any': [],
                'tech_hints_all': [],
                'specializations_any': [],
                'risk_signals_any': [],
                'auth_session': False,
                'capabilities_any': [],
                'capabilities_all': [],
                'confidence_min': {},
                'confidence_min_any': {},
                'endpoint_pattern_any': [],
                'param_any': [],
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://github.com/flarum/framework/security/advisories/GHSA-733r-8xcp-w9mr',
            'https://github.com/flarum/flarum-core/commit/ee8b3b4ad1413a2b0971fdd9e40f812d2a3a9d3a',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-21641',
        ],
        'cve': 'CVE-2024-21641',
    }

    def run(self):
        r = self.http_request(method="GET", path='/logout?return=http://oast.pro', allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.pro\\/?(\\/|[^.].*)?$', 'Set-Cookie: flarum_session=',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Flarum < 1.8.5 - Open Redirect detected",
                path='/logout?return=http://oast.pro',
            )
            return True
        return False

