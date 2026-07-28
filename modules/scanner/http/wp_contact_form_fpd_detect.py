#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Contact Form plugin files are publicly accessible without ABSPATH protection, exposing sensitive ser."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Contact Form - Full Path Disclosure Detection',
        'description': 'WordPress Contact Form plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'wordpress', 'fpd', 'contact-form', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
    }

    def run(self):
        for path in ('/wp-content/plugins/flamix-bitrix24-and-contact-forms-7-integrations/includes/vendor/mobiledetect/mobiledetectlib/export/exportToJSON.php', '/wp-content/plugins/cf7-salesforce/vendor/mobiledetect/mobiledetectlib/export/exportToJSON.php', '/concrete/vendor/mobiledetect/mobiledetectlib/export/exportToJSON.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('plugins/flamix-bitrix24', 'plugins/cf7-salesforce', 'mobiledetect/mobiledetectlib', 'Fatal error', 'Uncaught Error:', 'Done. Check',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='low',
                    reason="WordPress Contact Form - Full Path Disclosure detected",
                    path=path,
                )
                return True
        return False

