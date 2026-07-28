#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JustBoil."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JustBoil.me Images Plugin - Exposed Image Upload Detection',
        'description': "JustBoil.me Images Plugin for TinyMCE contains an exposed dialog interface that could lead to potential security vulnerabilities. The plugin's dialog-v4.htm file is accessible without proper access controls, which may allow unauthorized access to image upload functionality.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'justboil', 'tinymce', 'plugin', 'exposure', 'misconfig', 'vuln'],
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
        'references': ['https://cxsecurity.com/issue/WLB-2019050108'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/plugins/generic/tinymce/plugins/justboil.me/dialog-v4.htm', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('JustBoil.me Images Plugin', 'TinyMCE', 'upload_infobar',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="JustBoil.me Images Plugin - Exposed Image Upload detected",
                path='/plugins/generic/tinymce/plugins/justboil.me/dialog-v4.htm',
            )
            return True
        return False

