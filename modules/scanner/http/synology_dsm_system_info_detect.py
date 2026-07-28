#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected the disclosure of Synology DiskStation Manager (DSM) system information via the SYNO."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Synology DSM System Info - Detect',
        'description': 'Detected the disclosure of Synology DiskStation Manager (DSM) system information via the SYNO.API.Info endpoint, identifying all available APIs, versions, and installed packages returned without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'synology', 'dsm', 'misconfig', 'diskstation-manager'],
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
        'references': ['https://www.synology.com/en-us/dsm'],
    }

    def run(self):
        path = '/webapi/entry.cgi?api=SYNO.API.Info&version=1&method=query&query=all'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('SYNO.Core.', 'SYNO.FileStation.', 'SYNO.DSM.',)
        header_any = ('application/json',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='info',
                reason='Synology DSM System Info detected',
                path=path,
            )
            return True
        return False

