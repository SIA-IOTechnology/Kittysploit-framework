#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FortiOS Web User Interface in 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fortinet FortiOS - Open Redirect/Cross-Site Scripting Detection',
        'description': 'FortiOS Web User Interface in 5.0.x before 5.0.13, 5.2.x before 5.2.3, and 5.4.x before 5.4.0 allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks or cross-site scripting attacks via the "redirect" parameter to "login."',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2016', 'redirect', 'fortinet', 'fortios', 'seclists', 'vuln'],
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
            'http://www.fortiguard.com/advisory/fortios-open-redirect-vulnerability',
            'https://nvd.nist.gov/vuln/detail/CVE-2016-3978',
            'http://seclists.org/fulldisclosure/2016/Mar/68',
            'http://www.securitytracker.com/id/1035332',
        ],
        'cve': 'CVE-2016-3978',
    }

    def run(self):
        r = self.http_request(method="GET", path='/login?redir=http://www.interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Fortinet FortiOS - Open Redirect/Cross-Site Scripting detected",
                path='/login?redir=http://www.interact.sh',
            )
            return True
        return False

