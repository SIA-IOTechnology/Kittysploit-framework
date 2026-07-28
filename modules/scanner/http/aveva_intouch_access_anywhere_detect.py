#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected AVEVA InTouch Access Anywhere was a secure gateway that provided browser-based remote access to InTou."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AVEVA InTouch Access Anywhere - Panel Detection',
        'description': 'Detected AVEVA InTouch Access Anywhere was a secure gateway that provided browser-based remote access to InTouch HMI applications over the internet. It was widely used in industrial process control, utilities, and manufacturing environments. Exposed instances may have provided access to industrial HMI displays and SCADA interfaces.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'ics', 'scada', 'aveva', 'intouch', 'hmi'],
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
            'https://www.aveva.com/en/products/intouch-hmi/',
            'https://www.aveva.com/en/products/intouch-access-anywhere/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/AccessAnywhere/start.html', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Access Anywhere', 'AccessAnywhere',)
        body_all = ('AppName', 'OnClickConnect', 'ericom', 'InTouch',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='info',
                reason="AVEVA InTouch Access Anywhere detected",
                path='/AccessAnywhere/start.html',
            )
            return True
        return False

