#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Novius OS 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Novius OS 5.0.1-elche - Open Redirect Detection',
        'description': 'Novius OS 5.0.1 (Elche) allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL in the redirect parameter to admin/nos/login.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'packetstorm', 'redirect', 'novius', 'novius-os', 'xss', 'vuln'],
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
            'https://packetstormsecurity.com/files/132478/Novius-OS-5.0.1-elche-XSS-LFI-Open-Redirect.html',
            'https://vuldb.com/?id.76181',
            'http://packetstormsecurity.com/files/132478/Novius-OS-5.0.1-elche-XSS-LFI-Open-Redirect.html',
            'https://nvd.nist.gov/vul n/detail/CVE-2015-5354',
            'https://www.exploit-db.com/exploits/37439/',
        ],
        'cve': 'CVE-2015-5354',
    }

    def run(self):
        r = self.http_request(method="GET", path='/novius-os/admin/nos/login?redirect=http://interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Novius OS 5.0.1-elche - Open Redirect detected",
                path='/novius-os/admin/nos/login?redirect=http://interact.sh',
            )
            return True
        return False

