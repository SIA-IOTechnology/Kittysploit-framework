#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Optergy Proton/Enterprise Building Management System contains an open redirect vulnerability."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Optergy Proton/Enterprise Building Management System - Open Redirect Detection',
        'description': 'Optergy Proton/Enterprise Building Management System contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'redirect', 'packetstorm', 'optergy', 'vuln'],
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
            'https://packetstormsecurity.com/files/155268/Optergy-Proton-Enterprise-BMS-2.3.0a-Open-Redirect.html',
            'https://applied-risk.com/resources/ar-2019-008',
            'https://cxsecurity.com/issue/WLB-2019110074',
            'https://applied-risk.com/labs/advisories',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-7275',
        ],
        'cve': 'CVE-2019-7275',
    }

    def run(self):
        r = self.http_request(method="GET", path='/updating.jsp?url=https://interact.sh/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Optergy Proton/Enterprise Building Management System - Open Redirect detected",
                path='/updating.jsp?url=https://interact.sh/',
            )
            return True
        return False

