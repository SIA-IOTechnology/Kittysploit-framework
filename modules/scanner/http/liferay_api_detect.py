#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Liferay /api/liferay - API Exposed."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Liferay /api/liferay - API Exposed Detection',
        'description': 'Detects Liferay /api/liferay - API Exposed.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'liferay', 'exposure', 'api', 'misconfig', 'vuln'],
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
            'https://github.com/ilmila/J2EEScan/blob/master/src/main/java/burp/j2ee/issues/impl/LiferayAPI.java',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/liferay', allow_redirects=False)
        if not r or r.status_code != 404:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('text/html',)
        body_regexes = ('.*Internal Server Error.*An error occurred while accessing the requested resource\\..*',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='info',
                reason="Liferay /api/liferay - API Exposed detected",
                path='/api/liferay',
            )
            return True
        return False

