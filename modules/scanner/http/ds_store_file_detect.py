#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DS_Store File - Exposed Detection',
        'description': "A .DS_Store file was found. This file may contain names of files that exist on the server, including backups or other files that aren't meant to be publicly available.",
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'files', 'ds_store', 'config', 'vuln'],
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
        'references': ['https://github.com/lijiejie/ds_store_exp'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/.DS_Store', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        body_any = ('44534442', '0000000142756431', '\x00<\x00h\x00t\x00m\x00l', '\x00<\x00b\x00o\x00d\x00y',)
        header_any = ('accept-ranges: bytes', 'octet-stream',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='info',
                reason="DS_Store File - Exposed detected",
                path='/.DS_Store',
            )
            return True
        return False

