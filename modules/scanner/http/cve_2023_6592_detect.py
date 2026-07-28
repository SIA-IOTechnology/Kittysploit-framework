#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FastDup WordPress plugin < 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress FastDup <= 2.1.9  Sensitive Information Exposure - Directory Listing Detection',
        'description': 'FastDup WordPress plugin < 2.2 contains a directory listing vulnerability caused by lack of access restrictions in sensitive directories, letting attackers view export files, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wordpress', 'wp-plugin', 'fastdup', 'log', 'wp'],
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
            'https://wpscan.com/vulnerability/a39bb807-b143-4863-88ff-1783e407d7d4/',
            'https://wordpress.org/plugins/fastdup/',
            'https://plugins.trac.wordpress.org/changeset/3012664',
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/fastdup/fastdup-219-sensitive-information-exposure-via-directory-listing',
        ],
        'cve': 'CVE-2023-6592',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/fastdup/logs/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('Index of', 'Parent Directory',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress FastDup <= 2.1.9  Sensitive Information Exposure - Directory Listing detected",
                path='/wp-content/plugins/fastdup/logs/',
            )
            return True
        return False

