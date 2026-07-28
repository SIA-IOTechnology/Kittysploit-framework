#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BoltCMS login panel was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'BoltCMS Login Panel - Detect',
        'description': 'BoltCMS login panel was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'bolt', 'cms', 'login', 'boltcms'],
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
        'references': ['https://github.com/bolt/bolt'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/bolt/login', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_markers = (
            '<form action="/bolt/login"',
            '<img class="logo" alt="Bolt CMS logo"',
            '<img src="/app/view/img/bolt-logo.png"',
            '<link rel="shortcut icon" href="/app/view/img/favicon-bolt.ico">',
            '<link rel="stylesheet" href="/app/view/css/bolt-old-ie.css"',
            '<link rel="stylesheet" href="/app/view/css/bolt.css"',
            '<script src="/app/view/js/bolt.js"></script>',
            '<script src="/app/view/js/bolt.min.js"',
            '<script src="/assets/bolt.js"></script>',
            'Bolt requires JavaScript to function properly and continuing without it might corrupt or erase data.',
            'Bolt » Login',
            'Cookies are required to log on to Bolt. Please allow cookies.',
        )
        if any(m in body for m in body_markers):
            self.set_info(
                severity='info',
                reason="BoltCMS Login Panel detected",
                path='/bolt/login',
            )
            return True
        return False

