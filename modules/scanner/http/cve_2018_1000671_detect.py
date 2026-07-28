#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sympa version 6."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sympa version =>6.2.16 - Cross-Site Scripting Detection',
        'description': 'Sympa version 6.2.16 and later contains a URL Redirection to Untrusted Site vulnerability in the referer parameter of the wwsympa fcgi login action that can result in open redirection and reflected cross-site scripting via data URIs.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'redirect', 'sympa', 'debian', 'vuln'],
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
            'https://github.com/sympa-community/sympa/issues/268',
            'https://vuldb.com/?id.123670',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-1000671',
            'https://lists.debian.org/debian-lts-announce/2018/09/msg00023.html',
            'https://lists.debian.org/debian-lts-announce/2020/11/msg00015.html',
        ],
        'cve': 'CVE-2018-1000671',
    }

    def run(self):
        r = self.http_request(method="GET", path='/sympa?referer=http://interact.sh&passwd=&previous_action=&action=login&action_login=&previous_list=&list=&email=', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Sympa version =>6.2.16 - Cross-Site Scripting detected",
                path='/sympa?referer=http://interact.sh&passwd=&previous_action=&action=login&action_login=&previous_list=&list=&email=',
            )
            return True
        return False

