#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Duplicator plugin before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Duplicator <1.4.7 - Authentication Bypass Detection',
        'description': 'WordPress Duplicator plugin before 1.4.7 is susceptible to authentication bypass. The plugin discloses the URL of the backup to unauthenticated visitors accessing the main installer endpoint. If the installer script has been run once by an administrator, this allows download of the full site backup without proper authentication.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wordpress', 'wp', 'wp-plugin', 'duplicator', 'wpscan', 'snapcreek', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://wpscan.com/vulnerability/f27d753e-861a-4d8d-9b9a-6c99a8a7ebe0',
            'https://wordpress.org/plugins/duplicator/',
            'https://github.com/SecuriTrust/CVEsLab/tree/main/CVE-2022-2551',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-2551',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-2551',
    }

    def run(self):
        for path in ('/wp-content/backups-dup-lite/dup-installer/main.installer.php?is_daws=1', '/wp-content/dup-installer/main.installer.php?is_daws=1'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ("<a href='../installer.php'>restart this install process</a>",)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="WordPress Duplicator <1.4.7 - Authentication Bypass detected",
                    path=path,
                )
                return True
        return False

