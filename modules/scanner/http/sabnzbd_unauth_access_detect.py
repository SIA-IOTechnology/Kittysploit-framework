#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected SABnzbd found with the web interface accessible without authentication."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SABnzbd - Unauthenticated Web Interface Access Detection',
        'description': 'Detected SABnzbd found with the web interface accessible without authentication. The config page is exposed without login, leaking the API key, config file path, server parameters, and system information to unauthenticated users.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'sabnzbd', 'unauth', 'misconfig', 'exposure', 'iot'],
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
            'https://sabnzbd.org/wiki/extra/access-denied.html',
            'https://sabnzbd.org/wiki/configuration/4.5/api',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/config/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('var sabSession =', 'configTranslate', 'SABnzbd Config',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="SABnzbd - Unauthenticated Web Interface Access detected",
                path='/config/',
            )
            return True
        return False

