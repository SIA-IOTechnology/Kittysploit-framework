#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Glances < 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Glances - Information Disclosure Detection',
        'description': 'Glances < 4.5.1 contains an information disclosure vulnerability caused by unfiltered exposure of sensitive configuration data via the /api/4/config REST API endpoint, letting remote attackers access credentials, exploit requires API access.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'glances', 'exposure'],
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
            'https://github.com/nicolargo/glances/security/advisories/GHSA-gh4x-f7cq-wwx6',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-30928',
        ],
        'cve': 'CVE-2026-30928',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/4/config', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/json',)
        body_regexes = ('"password": "[A-Za-z0-9_@.#&+-;$]*",',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Glances - Information Disclosure detected",
                path='/api/4/config',
            )
            return True
        return False

