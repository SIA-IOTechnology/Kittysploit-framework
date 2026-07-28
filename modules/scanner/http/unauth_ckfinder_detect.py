#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The CKFinder file manager was found to be exposed without authentication, allowing unauthenticated users to di."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CKFinder - Unauthenticated Exposure Detection',
        'description': 'The CKFinder file manager was found to be exposed without authentication, allowing unauthenticated users to directly access its web interface. Due to this misconfiguration, attackers were able to browse server directories, upload arbitrary files, and manage existing files.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'ckfinder', 'misconfig', 'unauth', 'vuln'],
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
        'references': ['https://cksource.com/ckfinder', 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/ckfinder/ckfinder.html', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>CKFinder</title>', 'CKFinderFrameWindow', 'var ckfinder = new CKFinder', 'CKFinder.start()',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="CKFinder - Unauthenticated Exposure detected",
                path='/ckfinder/ckfinder.html',
            )
            return True
        return False

