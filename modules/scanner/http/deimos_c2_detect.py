#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DeimosC2 is a post-exploitation Command & Control (C2) tool that leverages multiple communication methods in o."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Deimos C2 - Detect',
        'description': 'DeimosC2 is a post-exploitation Command & Control (C2) tool that leverages multiple communication methods in order to control machines that have been compromised. DeimosC2 server and agents works on, and has been tested on, Windows, Darwin, and Linux.It is entirely written in Golang with a front end written in Vue.js.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'c2', 'ir', 'osint', 'deimosc2', 'vuln'],
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
        'references': ['https://twitter.com/MichalKoczwara/status/1551632627387473920'],
    }

    def run(self):
        path = '/login'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>Deimos C2</title>',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='info',
                reason='Deimos C2 detected',
                path=path,
            )
            return True
        return False

