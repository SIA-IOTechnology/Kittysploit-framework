#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in Hoteldruid Panel allows remote unauthenticated users access to the management portal withou."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Hoteldruid Management Panel Access Detection',
        'description': 'A vulnerability in Hoteldruid Panel allows remote unauthenticated users access to the management portal without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'hoteldruid', 'panel', 'unauth', 'vuln'],
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
            'https://github.com/nomi-sec/PoC-in-GitHub/blob/master/2021/CVE-2021-42949.json',
            'https://www.hoteldruid.com/',
        ],
    }

    def run(self):
        for path in ('/hoteldruid/inizio.php', '/inizio.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('<title> HotelDruid </title>', '<b>INSERT:</b>', '<b>TABLES:</b>',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Hoteldruid Management Panel Access detected",
                    path=path,
                )
                return True
        return False

