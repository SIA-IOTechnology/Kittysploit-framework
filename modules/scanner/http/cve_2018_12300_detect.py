#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seagate NAS OS 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Seagate NAS OS 4.3.15.1 - Open Redirect Detection',
        'description': 'Seagate NAS OS 4.3.15.1 contains an open redirect vulnerability in echo-server.html, which can allow an attacker to disclose information in the referer header via the state URL parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'redirect', 'seagate', 'nasos', 'vuln'],
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
            'https://blog.securityevaluators.com/invading-your-personal-cloud-ise-labs-exploits-the-seagate-stcr3000101-ecf89de2170',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-12300',
        ],
        'cve': 'CVE-2018-12300',
    }

    def run(self):
        r = self.http_request(method="GET", path='/echo-server.html?code=test&state=http://www.interact.sh#', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        server = r.headers.get("Server") or r.headers.get("server") or ""
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Seagate NAS OS 4.3.15.1 - Open Redirect detected",
                path='/echo-server.html?code=test&state=http://www.interact.sh#',
            )
            return True
        return False

