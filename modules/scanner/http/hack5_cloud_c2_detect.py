#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloud C² is a self-hosted web-based command and control suite for networked Hak5 gear that lets you pentest fr."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Hack5 Cloud C2 - Detect',
        'description': 'Cloud C² is a self-hosted web-based command and control suite for networked Hak5 gear that lets you pentest from anywhere. Linux, Mac and Windows computers can host the Cloud C² server while Hak5 gear such as the WiFi Pineapple, LAN Turtle and Packet Squirrel can be provisioned as clients.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'c2', 'ir', 'osint', 'hack5c2', 'vuln'],
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
        'references': ['https://twitter.com/fofabot/status/1742737671037091854'],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>Hak5 Cloud C²</title>',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='info',
                reason='Hack5 Cloud C2 detected',
                path=path,
            )
            return True
        return False

