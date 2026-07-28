#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Incorrect Access Control in FXServer version's v9601 and prior, for CFX."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FXServer < v9601 - Information Exposure Detection',
        'description': "Incorrect Access Control in FXServer version's v9601 and prior, for CFX.re FiveM, allows unauthenticated users to modify and read userdata via exposed api endpoint.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'fxserver', 'info-leak', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/UwUtisum/CVE-2024-46310',
            'https://vulmon.com/vulnerabilitydetails?qid=CVE-2024-46310',
            'https://vulners.com/githubexploit/D31ED8EC-1E21-54F9-AD42-778DAFBC8B4E',
        ],
        'cve': 'CVE-2024-46310',
    }

    def run(self):
        path = '/players.json'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('endpoint', 'id', 'identifiers', 'name', 'ping',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='FXServer < v9601 - Information Exposure detected', path=path)
            return True
        return False

