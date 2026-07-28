#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Django 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Django - Open Redirect Detection',
        'description': 'Django 1.11.x before 1.11.15 and 2.0.x before 2.0.8 contains an open redirect vulnerability. If django.middleware.common.CommonMiddleware and APPEND_SLASH settings are selected, and if the project has a URL pattern that accepts any path ending in a slash, an attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'django', 'redirect', 'djangoproject', 'vuln'],
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
            'https://www.djangoproject.com/weblog/2018/aug/01/security-releases/',
            'https://usn.ubuntu.com/3726-1/',
            'http://web.archive.org/web/20211206044224/https://securitytracker.com/id/1041403',
            'https://www.debian.org/security/2018/dsa-4264',
            'https://access.redhat.com/errata/RHSA-2019:0265',
        ],
        'cve': 'CVE-2018-14574',
    }

    def run(self):
        r = self.http_request(method="GET", path='//www.interact.sh', allow_redirects=False)
        if not r or r.status_code != 301:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('Location: https://www.interact.sh', 'Location: http://www.interact.sh',)
        if (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Django - Open Redirect detected",
                path='//www.interact.sh',
            )
            return True
        return False

