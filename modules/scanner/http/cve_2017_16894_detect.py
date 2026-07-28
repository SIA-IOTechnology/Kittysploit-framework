#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Laravel through 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Laravel <5.5.21 - Information Disclosure Detection',
        'description': 'Laravel through 5.5.21 is susceptible to information disclosure. An attacker can obtain sensitive information such as externally usable passwords via a direct request for the /.env URI. NOTE: CVE pertains only to the writeNewEnvironmentFileWith function in src/Illuminate/Foundation/Console/KeyGenerateCommand.php, which uses file_put_contents without restricting .env permissions. The .env filename is not used exclusively by Laravel.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'laravel', 'exposure', 'packetstorm', 'vkev', 'vuln'],
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
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16894',
            'https://packetstormsecurity.com/files/cve/CVE-2017-16894',
            'http://whiteboyz.xyz/laravel-env-file-vuln.html',
            'https://twitter.com/finnwea/status/967709791442341888',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-16894',
        ],
        'cve': 'CVE-2017-16894',
    }

    def run(self):
        r = self.http_request(method="GET", path='/.env', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('APP_NAME=', 'APP_DEBUG=', 'DB_PASSWORD=',)
        header_any = ('application/octet-stream',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Laravel <5.5.21 - Information Disclosure detected",
                path='/.env',
            )
            return True
        return False

