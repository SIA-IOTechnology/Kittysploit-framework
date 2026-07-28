#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Twonky Server is a media server software that allows streaming of multimedia content over DLNA/UPnP protocols."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Twonky Server - Exposure Detection',
        'description': 'Twonky Server is a media server software that allows streaming of multimedia content over DLNA/UPnP protocols. When exposed to the internet or an untrusted network without proper authentication or access restrictions, it may allow unauthorized users to browse and access media files, interact with server settings, or gather sensitive network information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'twonky', 'exposure', 'misconfig', 'vuln'],
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
        'references': ['https://lynxtechnology.com/twonky-server.html', 'https://download.twonky.com/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<title>TwonkyMedia</title>', 'Settings',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Twonky Server - Exposure detected",
                path='/',
            )
            return True
        return False

