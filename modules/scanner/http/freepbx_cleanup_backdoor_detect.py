#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FreePBX backdoor cleanup script used in 0-day exploitation of CVE-2025-57819 was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FreePBX - CVE-2025-57819 Backdoor Detection',
        'description': 'FreePBX backdoor cleanup script used in 0-day exploitation of CVE-2025-57819 was detected.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'modules': [
            'exploits/unix/webapp/http/freepbx_cve_2025_57819_rce',
        ],
        'tags': ['web', 'scanner', 'vulnerability', 'backdoor', 'sangoma', 'freepbx', 'vuln'],
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
            'https://community.freepbx.org/t/security-advisory-please-lock-down-your-administrator-access/107203',
        ],
        'cve': 'CVE-2025-57819',
    }

    def run(self):
        r = self.http_request(method="GET", path='/.clean.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('LOGS', 'Processing file', 'sed -i --follow-symlinks', '/var/log/asterisk/freepbx_security.log',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="FreePBX - CVE-2025-57819 Backdoor detected",
                path='/.clean.sh',
            )
            return True
        return False

