#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Snoop servlet is exposed in the Apache Tomcat examples directory."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Tomcat - Snoop Servlet Information Disclosure Detection',
        'description': 'The Snoop servlet is exposed in the Apache Tomcat examples directory.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'apache', 'jakarta', 'tomcat', 'exposure', 'info-leak', 'vuln'],
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
            'https://vulners.com/nessus/TOMCAT_SNOOP.NASL',
            'https://nvd.nist.gov/vuln/detail/CVE-2000-0760',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/examples/jsp/snp/snoop.jsp', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Request Information', 'Path info', 'Server name', 'Remote address',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='info',
                reason="Apache Tomcat - Snoop Servlet Information Disclosure detected",
                path='/examples/jsp/snp/snoop.jsp',
            )
            return True
        return False

