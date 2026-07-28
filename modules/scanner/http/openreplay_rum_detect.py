#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects OpenReplay (formerly Asayer) Session Replay & RUM SDK implementation."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenReplay RUM - Tech Detect',
        'description': 'Detects OpenReplay (formerly Asayer) Session Replay & RUM SDK implementation.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'rum', 'openreplay'],
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
        'references': ['https://github.com/openreplay/openreplay', 'https://docs.openreplay.com/en/sdk/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('static\\.openreplay\\.com/(?:latest|[0-9.]+)/openreplay\\.js', 'projectKey["\']?\\s*:\\s*["\'][A-Za-z0-9]{10,}["\']', 'ingestPoint["\']?\\s*:\\s*["\']https?://[^"\']+/ingest["\']', '[a-z0-9-]+\\.openreplay\\.cloud/ingest', 'window\\.OpenReplay\\s*=\\s*\\[', 'openReplay\\s*:\\s*\\{\\s*projectKey', 'window\\.asayer\\s*=\\s*\\[', 'asayer\\.io/ingest',)
        body_re_hit = any(re.search(rx, body, re.I) for rx in body_regexes)
        if body_re_hit:
            self.set_info(
                severity='info',
                reason="OpenReplay RUM - Tech detected",
                path='/',
            )
            return True
        return False

