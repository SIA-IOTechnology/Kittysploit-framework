#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LabKey Server Community Edition before 18."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LabKey Server Community Edition <18.3.0 - Open Redirect Detection',
        'description': 'LabKey Server Community Edition before 18.3.0-61806.763 contains an open redirect vulnerability via the /__r1/ returnURL parameter, which allows an attacker to redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'tenable', 'redirect', 'labkey', 'vuln'],
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
            'https://www.tenable.com/security/research/tra-2019-03',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-3912',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/StarCrossPortal/scalpel',
            'https://github.com/anonymous364872/Rapier_Tool',
        ],
        'cve': 'CVE-2019-3912',
    }

    def run(self):
        r = self.http_request(method="GET", path='/labkey/__r1/login-login.view?returnUrl=http://interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="LabKey Server Community Edition <18.3.0 - Open Redirect detected",
                path='/labkey/__r1/login-login.view?returnUrl=http://interact.sh',
            )
            return True
        return False

