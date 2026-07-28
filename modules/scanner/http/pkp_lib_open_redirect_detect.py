#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Public Knowledge Project pkp-lib is vulnerable to Open redirect due to a lack of input sanitization in the set."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Open Journal Systems pkp-lib - Open Redirect Detection',
        'description': 'Public Knowledge Project pkp-lib is vulnerable to Open redirect due to a lack of input sanitization in the setLocale function.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'pkp', 'ojs', 'open-journal-system', 'pkp-lib', 'redirect', 'vuln'],
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
        'references': ['https://github.com/pkp/pkp-lib/issues/7575'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php/index/user/setLocale/NEW_LOCALE?source=@oast.me', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)?(?:[a-zA-Z0-9\\-_\\.@]*){{Hostname}}@?(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.me\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Open Journal Systems pkp-lib - Open Redirect detected",
                path='/index.php/index/user/setLocale/NEW_LOCALE?source=@oast.me',
            )
            return True
        return False

