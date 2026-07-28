#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ricoh Web Image Monitor device was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ricoh Web Image Monitor - Detect',
        'description': 'Ricoh Web Image Monitor device was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'ricoh'],
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
        'references': ['https://support.ricoh.com/bb_v1oi/pub_e/oi_view/0001082/0001082137/view/intro/int/wim.htm'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/web/guest/en/websys/webArch/header.cgi', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_all = ('web image monitor</h3', 'ricoh',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='info',
                reason="Ricoh Web Image Monitor detected",
                path='/web/guest/en/websys/webArch/header.cgi',
            )
            return True
        return False

