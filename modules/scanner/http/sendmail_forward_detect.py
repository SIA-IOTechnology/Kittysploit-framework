#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sendmail ."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sendmail .forward File - Exposure Detection',
        'description': 'Sendmail .forward file is publicly accessible. This file is used to configure email forwarding and can expose sensitive information including email addresses, forwarding rules, and potentially executable commands (pipe to programs).',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'exposure', 'sendmail', 'config', 'mail', 'mta'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.sendmail.org/~ca/email/doc8.12/op-sh-4.html',
            'https://linux.die.net/man/5/forward',
        ],
    }

    def run(self):
        path = '/.forward'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_any = ('<html', '<!DOCTYPE', '<HTML',)
        ctype_any = ('text/plain',)
        body_regexes = ('[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"', '\\|[\\s]*/[a-zA-Z0-9/_.-]+', ':include:[\\s]*/[a-zA-Z0-9/_.-]+', '^/[a-zA-Z0-9/_.-]+/[a-zA-Z0-9/_.-]+$',)
        if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(
                severity='low',
                reason='Sendmail .forward File - Exposure detected',
                path=path,
            )
            return True
        return False

