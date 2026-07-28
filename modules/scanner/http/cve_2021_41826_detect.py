#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PlaceOS Authentication Service before 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PlaceOS 1.2109.1 - Open Redirection Detection',
        'description': 'PlaceOS Authentication Service before 1.29.10.0 allows app/controllers/auth/sessions_controller.rb open redirect.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'redirect', 'edb', 'packetstorm', 'placeos', 'place', 'vuln'],
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
            'https://github.com/PlaceOS/auth/issues/36',
            'https://www.exploit-db.com/exploits/50359',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-41826',
            'http://packetstormsecurity.com/files/164345/PlaceOS-1.2109.1-Open-Redirection.html',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-41826',
    }

    def run(self):
        r = self.http_request(method="GET", path='/auth/logout?continue=//interact.sh', allow_redirects=False)
        if not r or r.status_code not in (302, 301):
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="PlaceOS 1.2109.1 - Open Redirection detected",
                path='/auth/logout?continue=//interact.sh',
            )
            return True
        return False

