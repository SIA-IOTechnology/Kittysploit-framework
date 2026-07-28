#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress 3D FlipBook - PDF Flipbook Viewer, Flipbook Image Gallery plugin versions <= 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress 3D FlipBook <= 1.16.17 - Information Disclosure Detection',
        'description': 'WordPress 3D FlipBook - PDF Flipbook Viewer, Flipbook Image Gallery plugin versions <= 1.16.17 contain a missing authorization vulnerability in multiple AJAX endpoints. The fb3d_send_posts_in, fb3d_send_post_pages, fb3d_send_posts_in_pages, fb3d_send_posts_in_first_page, and fb3d_send_post_first_page handlers are registered with wp_ajax_nopriv hooks but fail to verify the post status of requested flipbook entries. This allows unauthenticated attackers to retrieve full metadata, PDF URLs, and configuration data of private, draft, and password-protected flipbook posts.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'wordpress', 'wp-plugin', 'wp', '3d-flipbook', 'exposure'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://patchstack.com/database/wordpress/plugin/interactive-3d-flipbook-powered-physics-engine/vulnerability/wordpress-3d-flipbook-pdf-embedder-pdf-flipbook-viewer-flipbook-image-gallery-plugin-1-16-17-missing-authorization-to-unauthenticated-private-draft-flipbook-data-exposure-vulnerability',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-1314',
        ],
        'cve': 'CVE-2026-1314',
    }

    def run(self):
        path = '/wp-content/plugins/interactive-3d-flipbook-powered-physics-engine/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('3D FlipBook',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-admin/admin-ajax.php?action=fb3d_send_posts'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"code":0', '"title":', '"post_type":"3d-flip-book"', '"post_name":""',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress 3D FlipBook <= 1.16.17 - Information Disclosure detected', path=path)
            return True
        return False

