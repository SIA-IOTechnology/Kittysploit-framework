#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Woody Ad Snippets prior to 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Woody Ad Snippets <2.2.5 - Cross-Site Scripting/Remote Code Execution Detection',
        'description': 'WordPress Woody Ad Snippets prior to 2.2.5 is susceptible to cross-site scripting and remote code execution via admin/includes/class.import.snippet.php, which allows unauthenticated options import as demonstrated by storing a cross-site scripting payload for remote code execution.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'wordpress', 'wp-plugin', 'xss', 'wp', 'webcraftic', 'vuln'],
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
            'https://github.com/GeneralEG/CVE-2019-15858',
            'https://blog.nintechnet.com/multiple-vulnerabilities-in-wordpress-woody-ad-snippets-plugin-lead-to-remote-code-execution/',
            'https://wpvulndb.com/vulnerabilities/9490',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-15858',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2019-15858',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/insert-php/readme.txt', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('2.2.5', 'Changelog', 'Woody ad snippets',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="WordPress Woody Ad Snippets <2.2.5 - Cross-Site Scripting/Remote Code Execution detected",
                path='/wp-content/plugins/insert-php/readme.txt',
            )
            return True
        return False

