#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in Twig PHP allows remote attackers to cause the product to execute arbitrary commands via an ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Twig PHP <2.4.4 template engine - SSTI Detection',
        'description': 'A vulnerability in Twig PHP allows remote attackers to cause the product to execute arbitrary commands via an SSTI vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'php', 'ssti', 'twig', 'vuln'],
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
    }

    def run(self):
        r = self.http_request(method="GET", path='/search?search_key=%7B%7B1337*1338%7D%7D', allow_redirects=False)
        if not r or r.status_code != 404:
            return False
        body = r.text or ""
        body_any = ('1788906',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Twig PHP <2.4.4 template engine - SSTI detected",
                path='/search?search_key=%7B%7B1337*1338%7D%7D',
            )
            return True
        return False

