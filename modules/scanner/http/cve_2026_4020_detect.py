#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gravity SMTP WordPress plugin <= 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gravity SMTP WordPress Plugin - Sensitive Information Exposure Detection',
        'description': 'Gravity SMTP WordPress plugin <= 2.1.4 contains a sensitive information exposure caused by an unrestricted REST API endpoint at /wp-json/gravitysmtp/v1/tests/mock-data, letting unauthenticated attackers retrieve detailed system configuration data, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'exposure', 'wordpress', 'wp-plugin', 'gravitysmtp', 'wp', 'unauthenticated', 'vkev'],
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
            'https://patchstack.com/database/vulnerability/wordpress-gravity-smtp-plugin-2-1-4-unauthenticated-sensitive-information-exposure-via-rest-api-vulnerability',
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/12a296db-ecc0-409b-8718-0c208504053a?source=cve',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-4020',
        ],
        'cve': 'CVE-2026-4020',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-json/gravitysmtp/v1/tests/mock-data?page=gravitysmtp-settings', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('gravitysmtp_admin_config', 'system_report_clipboard', 'feature_flags',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Gravity SMTP WordPress Plugin - Sensitive Information Exposure detected",
                path='/wp-json/gravitysmtp/v1/tests/mock-data?page=gravitysmtp-settings',
            )
            return True
        return False

