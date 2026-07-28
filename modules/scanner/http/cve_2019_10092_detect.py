#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache HTTP Server versions 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache HTTP Server <=2.4.39 - HTML Injection/Partial Cross-Site Scripting Detection',
        'description': 'Apache HTTP Server versions 2.4.0 through 2.4.39 are vulnerable to a limited cross-site scripting issue affecting the mod_proxy error page. An attacker could cause the link on the error page to be malformed and instead point to a page of their choice. This would only be exploitable where a server was set up with proxying enabled but was misconfigured in such a way that the Proxy Error page was displayed.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'apache', 'htmli', 'injection', 'vuln'],
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
            'https://github.com/DrunkenShells/Disclosures/tree/master/CVE-2019-10092-Limited%20Cross-Site%20Scripting%20in%20mod_proxy%20Error%20Page-Apache%20httpd',
            'https://httpd.apache.org/security/vulnerabilities_24.html',
            'https://lists.debian.org/debian-lts-announce/2019/09/msg00034.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-10092',
            'http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00004.html',
        ],
        'cve': 'CVE-2019-10092',
    }

    def run(self):
        r = self.http_request(method="GET", path='/%5cgoogle.com/evil.html', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Proxy Error', '<a href="/\\google.com/evil.html">',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Apache HTTP Server <=2.4.39 - HTML Injection/Partial Cross-Site Scripting detected",
                path='/%5cgoogle.com/evil.html',
            )
            return True
        return False

