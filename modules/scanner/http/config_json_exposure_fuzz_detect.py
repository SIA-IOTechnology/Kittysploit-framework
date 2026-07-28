#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects exposed JSON configuration files containing sensitive information including API keys, access tokens, A."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Exposed JSON Configuration Files Detection',
        'description': 'Detects exposed JSON configuration files containing sensitive information including API keys, access tokens, AWS credentials, database configurations, base URLs, file paths, and application settings. These files often contain production configurations and credentials that should not be publicly accessible.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'exposure', 'config', 'files', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
    }

    def run(self):
        for path in ('/config.json', '/configuration.json', '/settings.json', '/configs.json', '/conf.json', '/app.config.json', '/application.json', '/config.prod.json'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            server = r.headers.get("Server") or r.headers.get("server") or ""
            header_any = ('application/json', 'text/json', 'text/plain', 'text/html', 'text/php',)
            body_regexes = ('(?i)(\\"(api_key|apikey|token|secret|password|passwd|pwd|auth|access_key|secret_key)\\":\\s*\\"[^\\"]{8,}\\")', '(?i)(\\"(aws|azure|gcp|google|slack|github|twitter|facebook)\\":\\s*\\{)', '(?i)(\\"(host|endpoint|url|uri|connection|server)\\":\\s*\\"[^\\"]+\\")', '(?i)(\\"(username|user|uid|login)\\":\\s*\\"[^\\"]+\\")', '(?i)(\\"(db|database|mongo|mysql|postgresql|redis)\\":\\s*\\{)', '(?i)"production":\\s*(true|false)', '(?i)"baseUrl":\\s*"[^"]+"', '(?i)"(accessCode|recaptchaSiteKey|tokenExpire)":\\s*"[^"]+"', '(?i)"(fileUrl|loginAppUrl|aimBaseUrl)":\\s*"[^"]+"',)
            if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='critical',
                    reason="Exposed JSON Configuration Files detected",
                    path=path,
                )
                return True
        return False

