#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Magento Connect Manager installer was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Magento Connect Manager Installer - Detect',
        'description': 'Magento Connect Manager installer was detected. The software, available via /downloader/ location, requires Magento admin rights and uses the same authorization methods as for backend. If an attacker locates a matching pair of login/password, the installation will be compromised. An attacker can then discover backend URL for login (even if it is customized as described in Securing Magento /admin/) and install a Filesystem extension to obtain full access to all files and finally the database.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'magento', 'exposure'],
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
            'https://magentary.com/kb/restrict-access-to-magento-downloader/',
            'https://www.mageplaza.com/kb/how-to-stop-brute-force-attacks-magento.html#solution-3',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/downloader/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_markers = (
            'Magento Downloader',
            'Log In',
        )
        body_hit = any(m in body for m in body_markers)
        if body_hit:
            self.set_info(
                severity='info',
                reason="Magento Connect Manager Installer detected",
                path='/downloader/',
            )
            return True
        return False

