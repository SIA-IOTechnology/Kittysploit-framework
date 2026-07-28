#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ruby Gem credentials file is exposed, potentially leaking RubyGems API keys."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ruby Gem::ConfigFile Credential - Exposure Detection',
        'description': 'Ruby Gem credentials file is exposed, potentially leaking RubyGems API keys. The ~/.gem/credentials file stores authentication tokens for publishing gems to RubyGems.org or private gem servers.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'exposure', 'rubygems', 'credentials', 'config', 'token'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://guides.rubygems.org/rubygems-org-api/',
            'https://blog.rubygems.org/2020/07/28/api-key-leak.html',
        ],
    }

    def run(self):
        for path in ('/.gem/credentials', '/credentials', '/.gem/credentials.yaml'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = (':rubygems_api_key:', '<html', '<body', '<!DOCTYPE', '<script', '<?php',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="Ruby Gem::ConfigFile Credential - Exposure detected",
                    path=path,
                )
                return True
        return False

