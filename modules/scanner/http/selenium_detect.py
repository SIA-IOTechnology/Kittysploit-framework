#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Selenium was shown to have an exposed node."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Selenium - Node Exposure Detection',
        'description': 'Selenium was shown to have an exposed node. If a Selenium node is exposed without any form of authentication, remote command execution could be possible if chromium is configured. By default the port is 4444, still, most of the internet facing are done through reverse proxies.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'selenium', 'rce', 'chromium', 'vuln'],
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
            'https://nutcrackerssecurity.github.io/selenium.html',
            'https://labs.detectify.com/2017/10/06/guest-blog-dont-leave-your-grid-wide-open/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wd/hub', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('WebDriverRequest', '<title>WebDriver Hub</title>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Selenium - Node Exposure detected",
                path='/wd/hub',
            )
            return True
        return False

