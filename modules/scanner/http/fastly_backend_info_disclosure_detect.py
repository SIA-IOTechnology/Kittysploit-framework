#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Fastly CDN misconfigured and exposing backend/origin server IP addresses or hostnames in HTTP respons."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fastly Backend Server Information Disclosure Detection',
        'description': 'Detected Fastly CDN misconfigured and exposing backend/origin server IP addresses or hostnames in HTTP response headers.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'exposure', 'fastly', 'cdn', 'misconfig'],
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
        'references': ['https://developer.fastly.com/reference/http/http-headers/'],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        header_any = ('x-backend-server',)
        header_all = ('x-served-by', 'x-cache-hits', 'fastly',)
        if (any(m in headers for m in header_any)) and (all(m in headers for m in header_all)):
            self.set_info(
                severity='low',
                reason='Fastly Backend Server Information Disclosure detected',
                path=path,
            )
            return True
        return False

