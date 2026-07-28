#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected SonicWall Secure Mobile Access (SMA) appliances — an enterprise SSL-VPN gateway for secure remote acc."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SonicWall Secure Mobile Access (SMA) Panel - Detection',
        'description': 'Detected SonicWall Secure Mobile Access (SMA) appliances — an enterprise SSL-VPN gateway for secure remote access (SMA 1000/6200/7200 series).',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'sonicwall', 'sma', 'ssl-vpn', 'vpn', 'tech', 'login'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://www.sonicwall.com/products/remote-access/',
            'https://www.sonicwall.com/support/technical-documentation/?category=Secure%20Remote%20Access',
        ],
    }

    def run(self):
        for path in ('/', '/workplace/home.action'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_markers = ('/__extraweb__/', 'SonicWall',)
            body_word_hit = any(m in body for m in body_markers)
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_markers = ('EXTRAWEB_REFERER',)
            header_word_hit = any(m in headers for m in header_markers)
            header_regexes = ('(?i)Server:\\s*SMA/\\d',)
            if any(re.search(rx, headers, 0) for rx in header_regexes):
                self.set_info(
                    severity='info',
                    reason="SonicWall Secure Mobile Access (SMA) Panelion detected",
                    path=path,
                )
                return True
        return False

